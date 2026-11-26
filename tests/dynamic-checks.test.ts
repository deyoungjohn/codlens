import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { PlaywrightUnavailableError } from '../src/checks/dynamic/browser-probe.js';
import { runDynamicAudit } from '../src/checks/dynamic/index.js';
import { parseConfig } from '../src/core/config-loader.js';
import type { CodlensConfig } from '../src/types.js';

const servers: http.Server[] = [];

async function startServer(
  handler: http.RequestListener,
  host: '127.0.0.1' | '::1' = '127.0.0.1',
): Promise<string> {
  const server = http.createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, host, resolve));
  const addr = server.address() as AddressInfo;
  return host === '::1' ? `http://[::1]:${addr.port}` : `http://127.0.0.1:${addr.port}`;
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(Buffer.from(c)));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

function makeDynamicConfig(baseUrl: string): CodlensConfig {
  return parseConfig({
    projectName: 'dynamic-test-app',
    targetDir: '.',
    baseUrl,
    dynamic: {
      enabled: true,
      auth: {
        strategy: 'bearer',
        userA: { tokenEnvVar: 'CODLENS_TEST_USER_A', resourceId: 'order_a_1' },
        userB: { tokenEnvVar: 'CODLENS_TEST_USER_B', resourceId: 'order_b_2' },
      },
      protectedEndpoints: [{ method: 'GET', path: '/api/admin/users' }],
      idorTargets: [
        { method: 'GET', pathTemplate: '/api/orders/:id', ownerBResourceId: 'order_b_2' },
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
  delete process.env.CODLENS_TEST_USER_A;
  delete process.env.CODLENS_TEST_USER_B;
  while (servers.length > 0) {
    const srv = servers.pop()!;
    await new Promise<void>((resolve) => srv.close(() => resolve()));
  }
});

describe('dynamic audit suite (DYN-001 through DYN-008)', () => {
  it('catches all planted dynamic vulnerabilities DYN-001 through DYN-008 on a vulnerable server', async () => {
    process.env.CODLENS_TEST_USER_A = 'token_user_a';
    process.env.CODLENS_TEST_USER_B = 'token_user_b';

    const profile = { id: 'user_a', role: 'user', isAdmin: false };

    const baseUrl = await startServer(async (req, res) => {
      // Intentionally dangerous CORS: wildcard + credentials
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Credentials', 'true');

      if (req.method === 'OPTIONS') {
        res.statusCode = 204;
        res.end();
        return;
      }

      if (req.method === 'GET' && req.url === '/api/admin/users') {
        // DYN-001: Unprotected admin route
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify([{ id: 'user_a' }, { id: 'user_b' }]));
        return;
      }

      if (req.method === 'GET' && req.url === '/api/orders/order_b_2') {
        // DYN-002: IDOR — returns userB's order to userA
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ id: 'order_b_2', owner: 'user_b', total: 5000 }));
        return;
      }

      if (req.method === 'PATCH' && req.url === '/api/profile') {
        // DYN-003: Mass assignment
        const raw = await readBody(req);
        Object.assign(profile, JSON.parse(raw));
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(profile));
        return;
      }

      if (req.method === 'POST' && req.url === '/api/orders') {
        // DYN-004 & DYN-006: Accepts negative quantity and leaks stack trace + /home/ path on bad JSON
        const raw = await readBody(req);
        try {
          const body = JSON.parse(raw);
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ ok: true, quantity: body.quantity }));
        } catch (err) {
          res.statusCode = 500;
          res.end(
            `SyntaxError: ${(err as Error).message}\n    at Object.<anonymous> (/home/dev/app/server.js:42:15)`,
          );
        }
        return;
      }

      if (req.method === 'POST' && req.url === '/api/webhooks/paystack') {
        // DYN-005: Accepts unsigned webhook
        await readBody(req);
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ received: true }));
        return;
      }

      if (req.method === 'POST' && req.url === '/api/auth/login') {
        // DYN-007: No rate limiting
        await readBody(req);
        res.statusCode = 401;
        res.end(JSON.stringify({ error: 'Invalid credentials' }));
        return;
      }

      res.statusCode = 404;
      res.end('Not found');
    });

    const config = makeDynamicConfig(baseUrl);
    const results = await runDynamicAudit(config);

    const byId = new Map(results.map((r) => [r.moduleId, r]));
    expect(byId.get('DYN-001')?.findings.length).toBeGreaterThanOrEqual(1);
    expect(byId.get('DYN-002')?.findings.length).toBeGreaterThanOrEqual(1);
    expect(byId.get('DYN-003')?.findings.length).toBeGreaterThanOrEqual(1);
    expect(byId.get('DYN-004')?.findings.length).toBeGreaterThanOrEqual(2);
    expect(byId.get('DYN-005')?.findings.length).toBeGreaterThanOrEqual(1);
    expect(byId.get('DYN-006')?.findings.length).toBeGreaterThanOrEqual(2); // stack trace + /home/ path
    expect(byId.get('DYN-007')?.findings.length).toBeGreaterThanOrEqual(1);
    expect(byId.get('DYN-008')?.findings.length).toBeGreaterThanOrEqual(2); // CORS + missing headers

    // Verify raw auth token is never exposed in curl reproductions
    const serialized = JSON.stringify(results);
    expect(serialized).not.toContain('token_user_a');
    expect(serialized).toContain('$CODLENS_TEST_USER_A');
  });

  it('passes cleanly with zero CRITICAL/HIGH findings against a hardened IPv6 [::1] server', async () => {
    process.env.CODLENS_TEST_USER_A = 'hardened_token_a';
    let loginAttempts = 0;

    const baseUrl = await startServer(async (req, res) => {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');

      const isUserA = req.headers.authorization === 'Bearer hardened_token_a';

      if (req.method === 'OPTIONS') {
        res.statusCode = 204;
        res.end();
        return;
      }

      if (req.method === 'GET' && req.url === '/api/admin/users') {
        res.statusCode = 401;
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }

      if (req.method === 'GET' && req.url === '/api/orders/order_b_2') {
        res.statusCode = isUserA ? 403 : 401;
        res.end(JSON.stringify({ error: 'Forbidden' }));
        return;
      }

      if (req.method === 'PATCH' && req.url === '/api/profile') {
        await readBody(req);
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ id: 'user_a', role: 'user', isAdmin: false }));
        return;
      }

      if (req.method === 'POST' && req.url === '/api/orders') {
        const raw = await readBody(req);
        try {
          const body = JSON.parse(raw) as { quantity?: unknown; itemId?: unknown };
          if (
            typeof body.itemId !== 'string' ||
            body.itemId.length > 64 ||
            typeof body.quantity !== 'number' ||
            body.quantity <= 0
          ) {
            res.statusCode = 400;
            res.end(JSON.stringify({ error: 'Invalid input' }));
            return;
          }
          res.end(JSON.stringify({ ok: true }));
        } catch {
          res.statusCode = 400;
          res.end(JSON.stringify({ error: 'Malformed JSON' }));
        }
        return;
      }

      if (req.method === 'POST' && req.url === '/api/webhooks/paystack') {
        await readBody(req);
        res.statusCode = 401;
        res.end(JSON.stringify({ error: 'Invalid signature' }));
        return;
      }

      if (req.method === 'POST' && req.url === '/api/auth/login') {
        await readBody(req);
        loginAttempts++;
        if (loginAttempts > 5) {
          res.statusCode = 429;
          res.setHeader('Retry-After', '60');
          res.end(JSON.stringify({ error: 'Too many requests' }));
          return;
        }
        res.statusCode = 401;
        res.end(JSON.stringify({ error: 'Invalid credentials' }));
        return;
      }

      res.statusCode = 404;
      res.end(JSON.stringify({ error: 'Not found' }));
    }, '::1');

    const config = makeDynamicConfig(baseUrl);
    const results = await runDynamicAudit(config);
    const allFindings = results.flatMap((r) => r.findings);

    expect(allFindings).toEqual([]);
  });

  it('fails gracefully with setup instructions when --browser is requested without Playwright installed', async () => {
    const baseUrl = await startServer((_req, res) => {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.end('ok');
    });

    const config = parseConfig({
      projectName: 'browser-fallback-test',
      targetDir: '.',
      baseUrl,
      dynamic: { enabled: true },
    });

    await expect(runDynamicAudit(config, { browser: true })).rejects.toThrow(
      PlaywrightUnavailableError,
    );
  });
});
