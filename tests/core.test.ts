import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  ConfigLoadError,
  createDefaultConfig,
  loadConfig,
  parseConfig,
} from '../src/core/config-loader.js';
import { detectStack } from '../src/core/detector.js';
import {
  assertSafeRequestMethod,
  assertSafeTargetUrl,
  isLocalHost,
  normalizeHostname,
  SafetyGuardError,
  validateRequestMethod,
  validateTargetUrl,
} from '../src/core/safety-guard.js';

const tempDirs: string[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()!;
    await fs.rm(dir, { recursive: true, force: true });
  }
});

describe('safety-guard', () => {
  it('normalizes IPv6 bracketed hostnames and casing', () => {
    expect(normalizeHostname('[::1]')).toBe('::1');
    expect(normalizeHostname('::1')).toBe('::1');
    expect(normalizeHostname('LOCALHOST')).toBe('localhost');
  });

  it('allows localhost, 127.0.0.1, 0.0.0.0, and ::1 (bracketed and unbracketed)', () => {
    expect(isLocalHost('localhost')).toBe(true);
    expect(isLocalHost('127.0.0.1')).toBe(true);
    expect(isLocalHost('0.0.0.0')).toBe(true);
    expect(isLocalHost('::1')).toBe(true);
    expect(isLocalHost('[::1]')).toBe(true);

    expect(assertSafeTargetUrl('http://localhost:3000').allowed).toBe(true);
    expect(assertSafeTargetUrl('http://127.0.0.1:4000').allowed).toBe(true);
    expect(assertSafeTargetUrl('http://0.0.0.0:8080').allowed).toBe(true);
    const ipv6Result = assertSafeTargetUrl('http://[::1]:3000');
    expect(ipv6Result.allowed).toBe(true);
    expect(ipv6Result.normalizedHost).toBe('::1');
    expect(ipv6Result.isLocal).toBe(true);
  });

  it('blocks non-local URLs by default and allows them with --allow-non-local', () => {
    const blocked = validateTargetUrl('https://staging.example.com');
    expect(blocked.allowed).toBe(false);
    expect(blocked.isLocal).toBe(false);
    expect(() => assertSafeTargetUrl('https://prod.example.com')).toThrow(SafetyGuardError);

    const allowed = assertSafeTargetUrl('https://staging.example.com', { allowNonLocal: true });
    expect(allowed.allowed).toBe(true);
    expect(allowed.isLocal).toBe(false);
  });

  it('rejects invalid URLs and non-http protocols', () => {
    expect(validateTargetUrl('not-a-url').allowed).toBe(false);
    expect(validateTargetUrl('file:///etc/passwd').allowed).toBe(false);
  });

  it('blocks mutating HTTP methods against non-local hosts unless allowMutations is true', () => {
    // GET is allowed on non-local when allowNonLocal is true
    expect(
      validateRequestMethod('https://staging.example.com/api/orders', 'GET', {
        allowNonLocal: true,
      }).allowed,
    ).toBe(true);

    // POST / DELETE are blocked on non-local without allowMutations
    expect(() =>
      assertSafeRequestMethod('https://staging.example.com/api/orders', 'POST', {
        allowNonLocal: true,
        allowMutations: false,
      }),
    ).toThrow(SafetyGuardError);

    expect(() =>
      assertSafeRequestMethod('https://staging.example.com/api/orders/1', 'DELETE', {
        allowNonLocal: true,
        allowMutations: false,
      }),
    ).toThrow(SafetyGuardError);

    // Allowed when explicitly enabled
    expect(
      assertSafeRequestMethod('https://staging.example.com/api/orders', 'POST', {
        allowNonLocal: true,
        allowMutations: true,
      }).allowed,
    ).toBe(true);

    // Local hosts always allow mutating methods
    expect(assertSafeRequestMethod('http://[::1]:3000/api/orders', 'DELETE').allowed).toBe(true);
  });
});

describe('detector', () => {
  it('auto-detects Next.js, Prisma, Supabase, Paystack, OpenAI, and API routes', async () => {
    const dir = await makeTempDir('codlens-next-');
    await fs.mkdir(path.join(dir, '.git'));
    await fs.mkdir(path.join(dir, 'app/api/orders'), { recursive: true });
    await fs.mkdir(path.join(dir, 'prisma'), { recursive: true });
    await fs.mkdir(path.join(dir, 'supabase/migrations'), { recursive: true });
    await fs.mkdir(path.join(dir, 'node_modules/fake-pkg'), { recursive: true });

    await fs.writeFile(
      path.join(dir, 'package.json'),
      JSON.stringify({
        dependencies: {
          next: '15.0.0',
          '@prisma/client': '6.0.0',
          '@supabase/supabase-js': '2.0.0',
          openai: '4.0.0',
        },
        devDependencies: {
          typescript: '5.8.0',
        },
      }),
    );
    await fs.writeFile(path.join(dir, 'prisma/schema.prisma'), 'datasource db { provider = "postgresql" }');
    await fs.writeFile(
      path.join(dir, 'app/api/orders/route.ts'),
      `export async function POST(req: Request) { const sig = req.headers.get('x-paystack-signature'); return Response.json({ ok: true, sig }); }\n`,
    );
    // File inside node_modules should be ignored
    await fs.writeFile(
      path.join(dir, 'node_modules/fake-pkg/route.ts'),
      `export async function GET() { return new Response('ignored'); }\n`,
    );

    const stack = await detectStack(dir);

    expect(stack.hasGit).toBe(true);
    expect(stack.frameworks).toContain('nextjs');
    expect(stack.databases).toEqual(expect.arrayContaining(['prisma', 'supabase']));
    expect(stack.paymentProviders).toContain('paystack');
    expect(stack.aiSdks).toContain('openai');
    expect(stack.languages).toContain('typescript');
    expect(stack.routeFiles).toEqual(['app/api/orders/route.ts']);
  });

  it('auto-detects Python FastAPI, Stripe, Anthropic, and Firestore rules', async () => {
    const dir = await makeTempDir('codlens-py-');
    await fs.writeFile(
      path.join(dir, 'requirements.txt'),
      'fastapi==0.115.0\nstripe==11.0.0\nanthropic==0.40.0\n',
    );
    await fs.writeFile(path.join(dir, 'firestore.rules'), 'rules_version = "2";');
    await fs.writeFile(
      path.join(dir, 'main.py'),
      'from fastapi import FastAPI\napp = FastAPI()\n@app.get("/health")\ndef health(): return {"ok": True}\n',
    );

    const stack = await detectStack(dir);

    expect(stack.hasGit).toBe(false);
    expect(stack.frameworks).toContain('fastapi');
    expect(stack.databases).toContain('firebase');
    expect(stack.paymentProviders).toContain('stripe');
    expect(stack.aiSdks).toContain('anthropic');
    expect(stack.languages).toContain('python');
    expect(stack.routeFiles).toContain('main.py');
  });
});

describe('config-loader', () => {
  it('loads and validates a valid codlens.config.json and resolves relative targetDir', async () => {
    const dir = await makeTempDir('codlens-cfg-');
    const configPath = path.join(dir, 'codlens.config.json');
    await fs.writeFile(
      configPath,
      JSON.stringify({
        projectName: 'demo-app',
        targetDir: '../demo-app',
        baseUrl: 'http://localhost:3000',
        dynamic: {
          enabled: true,
          auth: {
            strategy: 'bearer',
            userA: { tokenEnvVar: 'CODLENS_USER_A_TOKEN', resourceId: 'ord_1' },
            userB: { tokenEnvVar: 'CODLENS_USER_B_TOKEN', resourceId: 'ord_2' },
          },
          protectedEndpoints: [{ method: 'GET', path: '/api/orders' }],
        },
      }),
    );

    const cfg = await loadConfig(configPath);
    expect(cfg.projectName).toBe('demo-app');
    expect(cfg.targetDir).toBe(path.resolve(dir, '../demo-app'));
    expect(cfg.static.ignorePaths).toContain('node_modules');
    expect(cfg.dynamic.protectedEndpoints).toHaveLength(1);
  });

  it('rejects hardcoded tokens in tokenEnvVar', () => {
    expect(() =>
      parseConfig({
        projectName: 'bad-cfg',
        targetDir: '.',
        dynamic: {
          auth: {
            strategy: 'bearer',
            userA: { tokenEnvVar: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def' },
          },
        },
      }),
    ).toThrow(ConfigLoadError);

    expect(() =>
      parseConfig({
        projectName: 'bad-cfg-2',
        targetDir: '.',
        dynamic: {
          auth: {
            strategy: 'bearer',
            userA: { tokenEnvVar: 'Bearer secret123' },
          },
        },
      }),
    ).toThrow(ConfigLoadError);
  });

  it('generates a valid default config with payment webhook hints', () => {
    const cfg = createDefaultConfig('/tmp/my-app', {
      baseUrl: 'http://127.0.0.1:4000',
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
    });

    expect(cfg.projectName).toBe('my-app');
    expect(cfg.baseUrl).toBe('http://127.0.0.1:4000');
    expect(cfg.dynamic.webhookEndpoints).toEqual([
      { provider: 'paystack', path: '/api/webhooks/paystack' },
    ]);
  });
});
