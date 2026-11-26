import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import type { Finding, ModuleResult, Severity } from '../../types.js';
import type { StaticScanContext } from './utils.js';

const execFileAsync = promisify(execFile);

interface NpmAuditJson {
  vulnerabilities?: Record<
    string,
    {
      name?: string;
      severity?: string;
      range?: string;
      fixAvailable?: boolean | { name?: string; version?: string };
    }
  >;
}

interface PnpmAuditJson {
  advisories?: Record<
    string,
    {
      module_name?: string;
      severity?: string;
      title?: string;
      vulnerable_versions?: string;
      patched_versions?: string;
    }
  >;
}

function mapSeverity(sev?: string): Severity {
  switch (sev?.toLowerCase()) {
    case 'critical':
      return 'CRITICAL';
    case 'high':
      return 'HIGH';
    case 'moderate':
      return 'MEDIUM';
    case 'low':
      return 'LOW';
    default:
      return 'INFO';
  }
}

async function exists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

async function execAuditStdout(
  cmd: string,
  args: string[],
  cwd: string,
): Promise<string> {
  try {
    const res = await execFileAsync(cmd, args, {
      cwd,
      timeout: 15000,
      maxBuffer: 4 * 1024 * 1024,
    });
    return res.stdout;
  } catch (err: unknown) {
    // npm/pnpm audit exits with code 1 when vulnerabilities are found while still writing JSON to stdout
    if (err && typeof err === 'object' && 'stdout' in err && typeof err.stdout === 'string') {
      return err.stdout;
    }
    return '';
  }
}

/**
 * Gracefully wraps `npm audit --json` and `pnpm audit --json --prod` when lockfiles exist.
 * Never errors out the audit if offline or if the CLI binary is unavailable.
 */
export async function runDepsAudit(ctx: StaticScanContext): Promise<ModuleResult> {
  const start = Date.now();
  const hasNpmLock = await exists(path.join(ctx.targetDir, 'package-lock.json'));
  const hasPnpmLock = await exists(path.join(ctx.targetDir, 'pnpm-lock.yaml'));
  const hasRequirements = await exists(path.join(ctx.targetDir, 'requirements.txt'));

  if (!hasNpmLock && !hasPnpmLock && !hasRequirements) {
    return {
      moduleId: 'STAT-DEPS',
      moduleName: 'Dependency Vulnerability Audit',
      kind: 'static',
      status: 'skipped',
      durationMs: Date.now() - start,
      findings: [],
      skippedReason: 'No package-lock.json, pnpm-lock.yaml, or requirements.txt found in target directory.',
    };
  }

  const findings: Finding[] = [];

  if (hasNpmLock) {
    try {
      const stdout = await execAuditStdout('npm', ['audit', '--json', '--omit=dev'], ctx.targetDir);
      if (stdout.trim().startsWith('{')) {
        const parsed = JSON.parse(stdout) as NpmAuditJson;
        const vulns = parsed.vulnerabilities ?? {};
        for (const [pkgName, info] of Object.entries(vulns)) {
          const severity = mapSeverity(info.severity);
          if (severity === 'INFO' || severity === 'LOW') continue;

          findings.push({
            id: 'STAT-DEPS',
            title: `Vulnerable npm dependency: ${info.name ?? pkgName} (${severity})`,
            severity,
            category: 'Production Safety',
            location: 'package-lock.json:1',
            evidence: `Package "${info.name ?? pkgName}" (${info.range ?? 'affected version'}) flagged by npm audit as ${info.severity ?? 'vulnerable'}.`,
            reproduction: `cd "${ctx.targetDir}" && npm audit --omit=dev`,
            whyItMatters:
              'Known vulnerabilities in third-party production dependencies can be exploited with public proof-of-concept tools even when your own application code is clean.',
            howToFix:
              `Run \`npm audit fix\` (or upgrade \`${info.name ?? pkgName}\` to a patched version) and re-run your test suite.\n\n` +
              `AI Fix Prompt: "Upgrade the vulnerable dependency '${info.name ?? pkgName}' in package.json to a patched version and verify compatibility."`,
          });
        }
      }
    } catch {
      // Gracefully ignore offline/network errors
    }
  } else if (hasPnpmLock) {
    try {
      const stdout = await execAuditStdout('pnpm', ['audit', '--json', '--prod'], ctx.targetDir);
      if (stdout.trim().startsWith('{')) {
        const parsed = JSON.parse(stdout) as PnpmAuditJson;
        const advisories = parsed.advisories ?? {};
        const seen = new Set<string>();
        for (const adv of Object.values(advisories)) {
          const pkgName = adv.module_name ?? 'unknown';
          const severity = mapSeverity(adv.severity);
          if (severity === 'INFO' || severity === 'LOW') continue;
          const dedupeKey = `${pkgName}:${adv.title ?? ''}`;
          if (seen.has(dedupeKey)) continue;
          seen.add(dedupeKey);

          findings.push({
            id: 'STAT-DEPS',
            title: `Vulnerable pnpm dependency: ${pkgName} (${severity})`,
            severity,
            category: 'Production Safety',
            location: 'pnpm-lock.yaml:1',
            evidence: `Package "${pkgName}" (${adv.vulnerable_versions ?? 'affected'}) — ${adv.title ?? 'security advisory'} (patched: ${adv.patched_versions ?? 'see advisory'}).`,
            reproduction: `cd "${ctx.targetDir}" && pnpm audit --prod`,
            whyItMatters:
              'Known vulnerabilities in third-party production dependencies can be exploited with public proof-of-concept tools even when your own application code is clean.',
            howToFix:
              `Upgrade \`${pkgName}\` to ${adv.patched_versions ?? 'a patched version'} (or add a \`pnpm.overrides\` entry) and re-run \`pnpm audit --prod\`.\n\n` +
              `AI Fix Prompt: "Upgrade or override the vulnerable pnpm dependency '${pkgName}' to a patched version (${adv.patched_versions ?? 'latest safe'}) and verify tests pass."`,
          });
        }
      }
    } catch {
      // Gracefully ignore offline/network errors or missing pnpm binary
    }
  }

  const hasHighOrCritical = findings.some(
    (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH',
  );

  return {
    moduleId: 'STAT-DEPS',
    moduleName: 'Dependency Vulnerability Audit',
    kind: 'static',
    status: hasHighOrCritical ? 'failed' : 'passed',
    durationMs: Date.now() - start,
    findings,
  };
}
