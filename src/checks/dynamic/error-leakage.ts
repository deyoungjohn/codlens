import type { Finding, HttpMethod, ModuleResult, Severity } from '../../types.js';
import {
  buildCurlCommand,
  joinUrl,
  resolveUserAuth,
  runDynamicModule,
  safeFetch,
  truncateEvidence,
  type DynamicContext,
} from './http-client.js';

interface LeakPattern {
  label: string;
  severity: Severity;
  regex: RegExp;
}

const LEAK_PATTERNS: LeakPattern[] = [
  {
    label: 'JavaScript/Node.js stack trace',
    severity: 'HIGH',
    regex: /\bat\s+(?:Object\.<anonymous>|Module\._compile|Function\.|async\s+\w+|\w+\s+\([^)]+:\d+:\d+\))/,
  },
  {
    label: 'Python traceback',
    severity: 'HIGH',
    regex: /Traceback \(most recent call last\):/,
  },
  {
    label: 'Raw SQL error message',
    severity: 'HIGH',
    regex: /\b(?:SQLITE_ERROR|PG::|psycopg2|syntax error at or near|ORA-\d{5}|You have an error in your SQL syntax|PrismaClientKnownRequestError)\b/i,
  },
  {
    label: 'Absolute server filesystem path',
    severity: 'MEDIUM',
    regex: /(?:\/home\/[a-zA-Z0-9._-]+\/|\/Users\/[a-zA-Z0-9._-]+\/|\/usr\/(?:local|src|lib)\/|\/app\/[a-zA-Z0-9._-]+\/|[A-Z]:\\[a-zA-Z0-9._-]+\\)/,
  },
];

export async function runErrorLeakageProbe(ctx: DynamicContext): Promise<ModuleResult> {
  return runDynamicModule('DYN-006', 'Error & Stack Trace Leakage', async () => {
    const findings: Finding[] = [];
    const seen = new Set<string>();
    const userA = resolveUserAuth(ctx.config.dynamic.auth, 'userA');
    const authHeaders = userA?.headers ?? {};

    const probes: Array<{
      method: HttpMethod;
      path: string;
      rawBody?: string;
      headers?: Record<string, string>;
    }> = [
      { method: 'GET', path: '/api/__codlens_nonexistent_route_404__' },
    ];

    for (const ep of ctx.config.dynamic.fuzzEndpoints) {
      probes.push({
        method: ep.method,
        path: ep.path,
        rawBody: '{"broken_json": [',
        headers: { ...authHeaders, 'Content-Type': 'application/json' },
      });
    }

    for (const probe of probes) {
      const res = await safeFetch(ctx, {
        method: probe.method,
        path: probe.path,
        headers: probe.headers,
        rawBody: probe.rawBody,
      });

      for (const pattern of LEAK_PATTERNS) {
        if (!pattern.regex.test(res.bodyText)) continue;

        const key = `${probe.method}:${probe.path}:${pattern.label}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const url = joinUrl(ctx.baseUrl, probe.path);
        findings.push({
          id: 'DYN-006',
          title: `${pattern.label} exposed in HTTP ${res.status} error response`,
          severity: pattern.severity,
          category: 'Production Safety',
          location: `${probe.method} ${probe.path}`,
          evidence: `HTTP ${res.status} leaked ${pattern.label}: ${truncateEvidence(res.bodyText)}`,
          reproduction: buildCurlCommand({
            method: probe.method,
            url,
            headers: probe.rawBody ? { 'Content-Type': 'application/json' } : undefined,
            authEnvVar: probe.rawBody ? userA?.envVarName : undefined,
            authStrategy: ctx.config.dynamic.auth?.strategy,
            body: probe.rawBody,
          }),
          whyItMatters:
            'Returning stack traces, SQL errors, or server filesystem paths in HTTP responses gives attackers a blueprint of your framework versions, database schema, and directory layout.',
          howToFix:
            'Add a global error handler that logs full stack traces server-side only and returns a generic JSON error (e.g., `{ "error": "Bad request" }` or `{ "error": "Internal server error" }`) to clients.\n\n' +
            `AI Fix Prompt: "Add a global error handler so ${probe.method} ${probe.path} logs detailed errors on the server and returns only a sanitized, generic error message without stack traces or file paths."`,
        });
      }
    }

    return { findings };
  });
}
