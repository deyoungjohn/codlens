import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { afterEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../src/core/config-loader.js';
import { computeAuditSummary } from '../src/core/runner.js';
import { renderMarkdownReport } from '../src/reporters/markdown-reporter.js';
import { ExitCode, type AuditReport, type Finding } from '../src/types.js';

const execFileAsync = promisify(execFile);
const CLI_PATH = path.resolve('dist/cli.js');

const tempDirs: string[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

async function runCli(
  args: string[],
  cwd?: string,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  try {
    const res = await execFileAsync(process.execPath, [CLI_PATH, ...args], {
      cwd,
      timeout: 15000,
    });
    return { exitCode: 0, stdout: res.stdout, stderr: res.stderr };
  } catch (err: unknown) {
    const e = err as { code?: number; stdout?: string; stderr?: string };
    return {
      exitCode: typeof e.code === 'number' ? e.code : 2,
      stdout: e.stdout ?? '',
      stderr: e.stderr ?? '',
    };
  }
}

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()!;
    await fs.rm(dir, { recursive: true, force: true });
  }
});

function sampleFinding(severity: Finding['severity']): Finding {
  return {
    id: 'STAT-001',
    title: 'Sample finding',
    severity,
    category: 'Secrets',
    location: 'src/app.ts:10',
    evidence: 'const key = "sk_l************";',
    reproduction: 'Inspect src/app.ts:10',
    whyItMatters: 'Secrets in source code can be stolen.',
    howToFix: 'Move secret to environment variable.',
  };
}

describe('reporters and runner verdict logic', () => {
  it('computes deterministic verdicts and exit codes', () => {
    const blocked = computeAuditSummary([sampleFinding('CRITICAL')]);
    expect(blocked.verdict).toBe('BLOCKED FOR LAUNCH');
    expect(blocked.exitCode).toBe(ExitCode.AUDIT_FAILED);

    const hardening = computeAuditSummary([sampleFinding('HIGH')]);
    expect(hardening.verdict).toBe('NEEDS HARDENING');
    expect(hardening.exitCode).toBe(ExitCode.AUDIT_FAILED);

    const readyWithNotes = computeAuditSummary([sampleFinding('MEDIUM'), sampleFinding('LOW')]);
    expect(readyWithNotes.verdict).toBe('LAUNCH READY WITH NOTES');
    expect(readyWithNotes.exitCode).toBe(ExitCode.PASS);

    const clean = computeAuditSummary([]);
    expect(clean.verdict).toBe('LAUNCH READY WITH NOTES');
    expect(clean.exitCode).toBe(ExitCode.PASS);
  });

  it('renders a learning-first Markdown report with verdict and sections', () => {
    const finding = sampleFinding('CRITICAL');
    const report: AuditReport = {
      tool: 'codlens',
      version: '0.1.0',
      timestamp: '2026-11-26T00:00:00.000Z',
      projectName: 'sample-app',
      targetDir: '/tmp/sample-app',
      detectedStack: {
        frameworks: ['express'],
        databases: ['prisma'],
        paymentProviders: ['paystack'],
        aiSdks: [],
        languages: ['typescript'],
        packageManagers: ['npm'],
        hasGit: true,
        routeFiles: ['src/server.ts'],
      },
      summary: computeAuditSummary([finding]),
      modules: [
        {
          moduleId: 'STAT-001',
          moduleName: 'Secret & Key Leakage',
          kind: 'static',
          status: 'failed',
          durationMs: 12,
          findings: [finding],
        },
      ],
      findings: [finding],
    };

    const md = renderMarkdownReport(report);
    expect(md).toContain('BLOCKED FOR LAUNCH');
    expect(md).toContain('[STAT-001] Sample finding');
    expect(md).toContain('**Why It Matters:**');
    expect(md).toContain('**How to Fix:**');
  });
});

describe('CLI end-to-end (init and run)', () => {
  it('codlens init generates a valid starter codlens.config.json without modifying target repo', async () => {
    const targetDir = await makeTempDir('codlens-cli-target-');
    const workDir = await makeTempDir('codlens-cli-work-');
    await fs.writeFile(
      path.join(targetDir, 'server.js'),
      [
        'app.get("/api/admin/users", (req, res) => res.json([]));',
        'app.get("/api/orders/:id", (req, res) => res.json({}));',
        'app.post("/api/webhooks/paystack", (req, res) => res.json({}));',
        'app.post("/api/auth/login", (req, res) => res.json({}));',
      ].join('\n'),
    );

    const outputPath = path.join(workDir, 'codlens.config.json');
    const res = await runCli(['init', '--target', targetDir, '--output', outputPath]);

    expect(res.exitCode).toBe(0);
    const loaded = await loadConfig(outputPath);
    expect(loaded.targetDir).toBe(targetDir);
    expect(loaded.dynamic.protectedEndpoints.some((e) => e.path === '/api/admin/users')).toBe(true);
    expect(loaded.dynamic.idorTargets.some((t) => t.pathTemplate === '/api/orders/:id')).toBe(true);
    expect(loaded.dynamic.webhookEndpoints.some((w) => w.path === '/api/webhooks/paystack')).toBe(
      true,
    );
    expect(loaded.dynamic.rateLimitEndpoints.some((r) => r.path === '/api/auth/login')).toBe(true);
  });

  it('codlens run --static-only exits with code 1 on vulnerable code and writes masked reports', async () => {
    const targetDir = await makeTempDir('codlens-cli-vuln-');
    const outDir = await makeTempDir('codlens-cli-reports-');
    const rawSecret = ['sk', 'live', 'abcdef1234567890abcdef'].join('_');
    await fs.writeFile(
      path.join(targetDir, 'index.ts'),
      `export const SECRET = "${rawSecret}";\n`,
    );

    const res = await runCli([
      'run',
      '--target',
      targetDir,
      '--static-only',
      '--skip-deps',
      '--out-dir',
      outDir,
    ]);

    expect(res.exitCode).toBe(1);
    expect(res.stdout).toContain('BLOCKED FOR LAUNCH');

    const reportFolders = await fs.readdir(outDir);
    expect(reportFolders).toHaveLength(1);
    const reportPath = path.join(outDir, reportFolders[0]);

    const jsonText = await fs.readFile(path.join(reportPath, 'codlens-report.json'), 'utf8');
    const mdText = await fs.readFile(path.join(reportPath, 'CODLENS_REPORT.md'), 'utf8');

    expect(jsonText).not.toContain(rawSecret);
    expect(mdText).not.toContain(rawSecret);
    expect(mdText).toContain('BLOCKED FOR LAUNCH');
    expect(mdText).toContain('sk_l****');
  });

  it('codlens run exits with code 2 when given a non-local URL without --allow-non-local', async () => {
    const targetDir = await makeTempDir('codlens-cli-nonlocal-');
    await fs.writeFile(path.join(targetDir, 'index.ts'), 'export const ok = true;\n');

    const res = await runCli([
      'run',
      '--target',
      targetDir,
      '--base-url',
      'https://example.com',
      '--skip-deps',
    ]);

    expect(res.exitCode).toBe(2);
    expect(res.stderr).toContain('Safety Guard Blocked');
  });
});
