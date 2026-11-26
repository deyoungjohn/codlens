import type { Finding, ModuleResult } from '../../types.js';
import {
  buildCurlCommand,
  joinUrl,
  runDynamicModule,
  safeFetch,
  type DynamicContext,
} from './http-client.js';

export async function runHeadersCorsProbe(ctx: DynamicContext): Promise<ModuleResult> {
  return runDynamicModule('DYN-008', 'CORS & Security Headers', async () => {
    const findings: Finding[] = [];
    const probePath =
      ctx.config.dynamic.protectedEndpoints[0]?.path ??
      ctx.config.static.publicEndpointsAllowlist[0] ??
      '/';
    const url = joinUrl(ctx.baseUrl, probePath);

    // 1. Check CORS with an untrusted Origin
    const evilOrigin = 'https://evil-codlens-probe.example';
    const corsRes = await safeFetch(ctx, {
      method: 'OPTIONS',
      path: probePath,
      headers: {
        Origin: evilOrigin,
        'Access-Control-Request-Method': 'GET',
      },
    }).catch(() =>
      safeFetch(ctx, {
        method: 'GET',
        path: probePath,
        headers: { Origin: evilOrigin },
      }),
    );

    const acao = corsRes.headers.get('access-control-allow-origin')?.trim() ?? '';
    const acac = corsRes.headers.get('access-control-allow-credentials')?.trim().toLowerCase() ?? '';

    if (acac === 'true' && (acao === '*' || acao === evilOrigin)) {
      findings.push({
        id: 'DYN-008',
        title: 'Dangerous credentialed CORS policy allows arbitrary origins',
        severity: 'HIGH',
        category: 'Production Safety',
        location: `OPTIONS ${probePath}`,
        evidence: `Access-Control-Allow-Origin: "${acao}" combined with Access-Control-Allow-Credentials: "${acac}"`,
        reproduction: buildCurlCommand({
          method: 'OPTIONS',
          url,
          headers: { Origin: evilOrigin, 'Access-Control-Request-Method': 'GET' },
        }),
        whyItMatters:
          'Allowing wildcard or reflected arbitrary origins alongside `Access-Control-Allow-Credentials: true` lets any malicious website make authenticated cross-origin requests on behalf of logged-in users and read private responses.',
        howToFix:
          'Restrict `Access-Control-Allow-Origin` to an explicit allowlist of trusted frontend origins (e.g., `process.env.FRONTEND_URL`) instead of `*` or blindly reflecting the `Origin` header.\n\n' +
          'AI Fix Prompt: "Configure CORS to allow only explicitly allowlisted frontend origins from environment variables rather than wildcard or reflected origins when credentials are enabled."',
      });
    }

    // 2. Check baseline security headers via GET
    const getRes = await safeFetch(ctx, {
      method: 'GET',
      path: probePath,
    });

    const missingHeaders: string[] = [];
    if (!getRes.headers.get('x-content-type-options')) {
      missingHeaders.push('X-Content-Type-Options: nosniff');
    }
    if (!getRes.headers.get('x-frame-options') && !getRes.headers.get('content-security-policy')) {
      missingHeaders.push('X-Frame-Options (or Content-Security-Policy frame-ancestors)');
    }

    if (missingHeaders.length > 0) {
      findings.push({
        id: 'DYN-008',
        title: `Missing baseline security headers (${missingHeaders.length})`,
        severity: 'LOW',
        category: 'Production Safety',
        location: `GET ${probePath}`,
        evidence: `Missing headers on HTTP ${getRes.status} response: ${missingHeaders.join(', ')}`,
        reproduction: buildCurlCommand({ method: 'GET', url }),
        whyItMatters:
          'Baseline security headers protect users against MIME-sniffing attacks and clickjacking with minimal configuration effort.',
        howToFix:
          'Add security headers middleware (e.g., `helmet()` in Express or `headers()` in `next.config.js`) to set `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and a Content-Security-Policy.\n\n' +
          'AI Fix Prompt: "Add baseline security headers (X-Content-Type-Options: nosniff, X-Frame-Options: DENY, and Content-Security-Policy) via Helmet or framework response header middleware."',
      });
    }

    return { findings };
  });
}
