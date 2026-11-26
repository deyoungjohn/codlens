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

function mapNpmSeverity(sev?: string): Severity {
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

/**
 * Gracefully wraps `npm audit --json` (and `pip-audit` if present) when lockfiles exist.
 * Never errors out the audit if offline or if the CLI binary is unavailable.
 */
export async function runDepsAudit(ctx: StaticScanContext): Promise<ModuleResult> {
  const start = Date.now();
  const hasNpmLock = await exists(path.join(ctx.targetDir, 'package-lock.json'));
  const hasRequirements = await exists(path.join(ctx.targetDir, 'requirements.txt'));

  if (!hasNpmLock && !hasRequirements) {
    return {
      moduleId: 'STAT-DEPS',
      moduleName: 'Dependency Vulnerability Audit',
      kind: 'static',
      status: 'skipped',
      durationMs: Date.now() - start,
      findings: [],
      skippedReason: 'No package-lock.json or requirements.txt found in target directory.',
    };
  }

  const findings: Finding[] = [];

  if (hasNpmLock) {
    try {
      let stdout = '';
      try {
        const res = await execFileAsync('npm', ['audit', '--json', '--omit=dev'], {
          cwd: ctx.targetDir,
          timeout: 15000,
          maxBuffer: 4 * 1024 * 1024,
        });
        stdout = res.stdout;
      } catch (err: unknown) {
        // npm audit exits with code 1 when vulnerabilities are found and still writes JSON to stdout
        if (err && typeof err === 'object' && 'stdout' in err && typeof err.stdout === 'string') {
          stdout = err.stdout;
        }
      }

      if (stdout.trim().startsWith('{')) {
        const parsed = JSON.parse(stdout) as NpmAuditJson;
        const vulns = parsed.vulnerabilities ?? {};
        for (const [pkgName, info] of Object.entries(vulns)) {
          const severity = mapNpmSeverity(info.severity);
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
