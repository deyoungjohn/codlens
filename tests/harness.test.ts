import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import type http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { afterEach, describe, expect, it } from 'vitest';
import { loadConfig, parseConfig } from '../src/core/config-loader.js';
import { runAudit } from '../src/core/runner.js';
import { ExitCode, type CodlensConfig } from '../src/types.js';

const execFileAsync = promisify(execFile);
const REPO_ROOT = path.resolve('.');
const VULN_DIR = path.join(REPO_ROOT, 'fixtures/vulnerable-canary');
const HARDENED_DIR = path.join(REPO_ROOT, 'fixtures/hardened-canary');
const CLI_PATH = path.join(REPO_ROOT, 'dist/cli.js');

const servers: http.Server[] = [];
const tempDirs: string[] = [];

async function listenEphemeral(
  server: http.Server,
  host: '127.0.0.1' | '::1' = '127.0.0.1',
): Promise<string> {
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, host, resolve));
  const addr = server.address() as AddressInfo;
  return host === '::1' ? `http://[::1]:${addr.port}` : `http://127.0.0.1:${addr.port}`;
}

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

async function runCli(
  args: string[],
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  try {
    const res = await execFileAsync(process.execPath, [CLI_PATH, ...args], {
      cwd: REPO_ROOT,
      timeout: 20000,
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

function buildCanaryConfig(projectName: string, targetDir: string, baseUrl: string): CodlensConfig {
  return parseConfig({
    projectName,
    targetDir,
    baseUrl,
    static: {
      ignorePaths: ['node_modules', '.next', 'dist', 'coverage'],
      publicEndpointsAllowlist: ['/api/health', '/api/auth/login', '/api/auth/register'],
    },
    dynamic: {
      enabled: true,
      auth: {
        strategy: 'bearer',
        userA: { tokenEnvVar: 'CODLENS_CANARY_USER_A', resourceId: 'order_a_123' },
        userB: { tokenEnvVar: 'CODLENS_CANARY_USER_B', resourceId: 'order_b_456' },
      },
      protectedEndpoints: [
        { method: 'GET', path: '/api/admin/users' },
        { method: 'GET', path: '/api/profile' },
      ],
      idorTargets: [
        { method: 'GET', pathTemplate: '/api/orders/:id', ownerBResourceId: 'order_b_456' },
      ],
      profileUpdateEndpoint: { method: 'PATCH', path: '/api/profile' },
      fuzzEndpoints: [
        {
          method: 'POST',
          path: '/api/orders',
          sampleValidBody: { itemId: 'item_1', quantity: 1 },
        },
      ],
      webhookEndpoints: [{ provider: 'paystack', path: '/api/webhooks/paystack' }],
      rateLimitEndpoints: [{ method: 'POST', path: '/api/auth/login', burstCount: 10 }],
    },
  });
}

afterEach(async () => {
  delete process.env.CODLENS_CANARY_USER_A;
  delete process.env.CODLENS_CANARY_USER_B;
  while (servers.length > 0) {
    const s = servers.pop()!;
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()!;
    await fs.rm(dir, { recursive: true, force: true });
  }
});

describe('Codlens end-to-end self-verification harness', () => {
  it('catches every planted vulnerability (STAT-001..STAT-007 and DYN-001..DYN-008) on vulnerable-canary', async () => {
    process.env.CODLENS_CANARY_USER_A = 'vuln_user_a_token';
    process.env.CODLENS_CANARY_USER_B = 'vuln_user_b_token';

    const { createVulnerableServer } = (await import(
      '../fixtures/vulnerable-canary/server.mjs'
    )) as { createVulnerableServer: () => http.Server };

    const baseUrl = await listenEphemeral(createVulnerableServer(), '127.0.0.1');
    const config = buildCanaryConfig('vulnerable-canary', VULN_DIR, baseUrl);
    const report = await runAudit(config, { skipDepsAudit: true });

    expect(report.summary.verdict).toBe('BLOCKED FOR LAUNCH');
    expect(report.summary.exitCode).toBe(ExitCode.AUDIT_FAILED);

    const triggeredIds = new Set(report.findings.map((f) => f.id));
    const expectedIds = [
      'STAT-001',
      'STAT-002',
      'STAT-003',
      'STAT-004',
      'STAT-005',
      'STAT-006',
      'STAT-007',
      'DYN-001',
      'DYN-002',
      'DYN-003',
      'DYN-004',
      'DYN-005',
      'DYN-006',
      'DYN-007',
      'DYN-008',
    ];
    for (const id of expectedIds) {
      expect(triggeredIds.has(id), `Expected check ${id} to trigger on vulnerable-canary`).toBe(
        true,
      );
    }

    // Ensure raw secrets and auth tokens never leak into report output
    const serialized = JSON.stringify(report);
    expect(serialized).not.toContain('sk_test_canary99887766');
    expect(serialized).not.toContain('vuln_user_a_token');
  });

  it('passes hardened-canary on IPv6 [::1] with zero CRITICAL and zero HIGH findings (exit code 0)', async () => {
    process.env.CODLENS_CANARY_USER_A = 'hardened_user_a_token';
    process.env.CODLENS_CANARY_USER_B = 'hardened_user_b_token';

    const { createHardenedServer } = (await import(
      '../fixtures/hardened-canary/server.mjs'
    )) as {
      createHardenedServer: (opts?: {
        userAToken?: string;
        userBToken?: string;
      }) => http.Server;
    };

    const baseUrl = await listenEphemeral(
      createHardenedServer({
        userAToken: 'hardened_user_a_token',
        userBToken: 'hardened_user_b_token',
      }),
      '::1',
    );
    const config = buildCanaryConfig('hardened-canary', HARDENED_DIR, baseUrl);
    const report = await runAudit(config, { skipDepsAudit: true });

    expect(report.summary.bySeverity.CRITICAL).toBe(0);
    expect(report.summary.bySeverity.HIGH).toBe(0);
    expect(report.summary.exitCode).toBe(ExitCode.PASS);
    expect(report.summary.verdict).toBe('LAUNCH READY WITH NOTES');
  });

  it('CLI Definition-of-Done checks: static-only exit 1 + masked reports, init starter config, and non-local exit 2', async () => {
    const outDir = await makeTempDir('codlens-dod-reports-');
    const initDir = await makeTempDir('codlens-dod-init-');

    // 1. codlens run --target ./fixtures/vulnerable-canary --static-only -> exit 1 + valid masked reports
    const staticRun = await runCli([
      'run',
      '--target',
      './fixtures/vulnerable-canary',
      '--static-only',
      '--skip-deps',
      '--out-dir',
      outDir,
    ]);
    expect(staticRun.exitCode).toBe(1);

    const folders = await fs.readdir(outDir);
    expect(folders).toHaveLength(1);
    const reportFolder = path.join(outDir, folders[0]);
    const jsonRaw = await fs.readFile(path.join(reportFolder, 'codlens-report.json'), 'utf8');
    const mdRaw = await fs.readFile(path.join(reportFolder, 'CODLENS_REPORT.md'), 'utf8');

    const parsedJson = JSON.parse(jsonRaw) as { summary: { exitCode: number; verdict: string } };
    expect(parsedJson.summary.exitCode).toBe(1);
    expect(parsedJson.summary.verdict).toBe('BLOCKED FOR LAUNCH');
    expect(jsonRaw).not.toContain('sk_test_canary99887766');
    expect(mdRaw).not.toContain('sk_test_canary99887766');
    expect(mdRaw).toContain('BLOCKED FOR LAUNCH');

    // 2. codlens init --target ./fixtures/vulnerable-canary -> valid starter codlens.config.json
    const initOut = path.join(initDir, 'codlens.config.json');
    const initRun = await runCli([
      'init',
      '--target',
      './fixtures/vulnerable-canary',
      '--output',
      initOut,
    ]);
    expect(initRun.exitCode).toBe(0);
    const loadedConfig = await loadConfig(initOut);
    expect(loadedConfig.projectName).toBe('vulnerable-canary');
    expect(loadedConfig.targetDir).toBe(VULN_DIR);

    // 3. Non-localhost URL refused without --allow-non-local -> exit 2
    const nonLocalRun = await runCli([
      'run',
      '--target',
      './fixtures/hardened-canary',
      '--base-url',
      'https://production.example.com',
      '--skip-deps',
    ]);
    expect(nonLocalRun.exitCode).toBe(2);
    expect(nonLocalRun.stderr).toContain('Safety Guard Blocked');
  });
});
