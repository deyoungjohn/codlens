import type { Finding, ModuleResult } from '../../types.js';
import {
  buildCurlCommand,
  joinUrl,
  runDynamicModule,
  safeFetch,
  type DynamicContext,
} from './http-client.js';

export async function runRateLimitProbe(ctx: DynamicContext): Promise<ModuleResult> {
  return runDynamicModule('DYN-007', 'Rate Limiting Check', async () => {
    const endpoints = ctx.config.dynamic.rateLimitEndpoints;
    if (endpoints.length === 0) {
      return {
        findings: [],
        skippedReason: 'No rateLimitEndpoints configured in codlens.config.json.',
      };
    }

    const findings: Finding[] = [];

    for (const ep of endpoints) {
      const burstCount = ep.burstCount ?? 25;
      let saw429 = false;
      let sawRetryAfter = false;
      let lastStatus = 0;

      for (let i = 0; i < burstCount; i++) {
        const res = await safeFetch(ctx, {
          method: ep.method,
          path: ep.path,
          body:
            ep.method === 'POST' || ep.method === 'PUT' || ep.method === 'PATCH'
              ? { email: `codlens_burst_${i}@example.com`, password: 'invalid_password' }
              : undefined,
          retries: 0,
        });

        lastStatus = res.status;
        if (res.status === 429) {
          saw429 = true;
          break;
        }
        if (res.headers.has('retry-after')) {
          sawRetryAfter = true;
          break;
        }
      }

      if (!saw429 && !sawRetryAfter) {
        const url = joinUrl(ctx.baseUrl, ep.path);
        findings.push({
          id: 'DYN-007',
          title: `No rate limiting detected on ${ep.method} ${ep.path} after ${burstCount} rapid requests`,
          severity: 'MEDIUM',
          category: 'Production Safety',
          location: `${ep.method} ${ep.path}`,
          evidence: `Sent ${burstCount} sequential requests; none returned HTTP 429 or Retry-After (last status: HTTP ${lastStatus}).`,
          reproduction: `for i in $(seq 1 ${burstCount}); do ${buildCurlCommand({ method: ep.method, url, headers: { 'Content-Type': 'application/json' }, body: '{"email":"test@example.com","password":"wrong"}' })}; done`,
          whyItMatters:
            'Without rate limiting on login, OTP, or AI endpoints, attackers can brute-force user passwords, spam emails, or drain paid LLM API credits at high speed.',
          howToFix:
            'Apply rate-limiting middleware (e.g., `express-rate-limit`, Upstash Ratelimit, or SlowAPI) to return HTTP 429 with a `Retry-After` header after a small threshold of rapid requests.\n\n' +
            `AI Fix Prompt: "Add rate-limiting middleware to ${ep.method} ${ep.path} (e.g., max 10 requests per minute per IP) that responds with HTTP 429 Too Many Requests and a Retry-After header."`,
        });
      }
    }

    return { findings };
  });
}
