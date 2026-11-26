import type { Finding, ModuleResult } from '../../types.js';
import {
  buildCurlCommand,
  joinUrl,
  runDynamicModule,
  safeFetch,
  truncateEvidence,
  type DynamicContext,
} from './http-client.js';

export async function runAuthBypassProbe(ctx: DynamicContext): Promise<ModuleResult> {
  return runDynamicModule('DYN-001', 'Unauthenticated Access Check', async () => {
    const endpoints = ctx.config.dynamic.protectedEndpoints;
    if (endpoints.length === 0) {
      return {
        findings: [],
        skippedReason: 'No protectedEndpoints configured in codlens.config.json.',
      };
    }

    const findings: Finding[] = [];

    for (const ep of endpoints) {
      const res = await safeFetch(ctx, {
        method: ep.method,
        path: ep.path,
      });

      const url = joinUrl(ctx.baseUrl, ep.path);
      const curl = buildCurlCommand({ method: ep.method, url });

      if (res.status === 200 || res.status === 201 || res.status >= 500) {
        const isServerCrash = res.status >= 500;
        findings.push({
          id: 'DYN-001',
          title: isServerCrash
            ? `Protected endpoint crashed (HTTP ${res.status}) on unauthenticated request`
            : `Protected endpoint accessible without authentication (HTTP ${res.status})`,
          severity: 'CRITICAL',
          category: 'Auth & Access Control',
          location: `${ep.method} ${ep.path}`,
          evidence: `HTTP ${res.status} — ${truncateEvidence(res.bodyText || '<empty body>')}`,
          reproduction: curl,
          whyItMatters: isServerCrash
            ? 'Unauthenticated requests should be rejected cleanly with HTTP 401/403 before business logic runs. A 500 crash indicates missing auth guards (e.g., dereferencing an undefined `req.user`).'
            : 'Anyone on the internet can call this protected endpoint without logging in and read or modify private application data.',
          howToFix:
            `Enforce server-side authentication middleware on \`${ep.method} ${ep.path}\` so unauthenticated requests immediately receive HTTP 401 Unauthorized.\n\n` +
            `AI Fix Prompt: "Protect ${ep.method} ${ep.path} with server-side authentication middleware that returns HTTP 401 before executing any handler logic when no valid token or session is present."`,
        });
      }
    }

    return { findings };
  });
}
