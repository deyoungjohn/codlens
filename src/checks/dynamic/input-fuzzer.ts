import type { Finding, ModuleResult } from '../../types.js';
import {
  buildCurlCommand,
  joinUrl,
  resolveUserAuth,
  runDynamicModule,
  safeFetch,
  truncateEvidence,
  type DynamicContext,
} from './http-client.js';

export async function runInputFuzzerProbe(ctx: DynamicContext): Promise<ModuleResult> {
  return runDynamicModule('DYN-004', 'Input Fuzzing & Negative Values', async () => {
    const endpoints = ctx.config.dynamic.fuzzEndpoints;
    if (endpoints.length === 0) {
      return {
        findings: [],
        skippedReason: 'No fuzzEndpoints configured in codlens.config.json.',
      };
    }

    const userA = resolveUserAuth(ctx.config.dynamic.auth, 'userA');
    const authHeaders = userA?.headers ?? {};
    const findings: Finding[] = [];

    for (const ep of endpoints) {
      const url = joinUrl(ctx.baseUrl, ep.path);

      // 1. Malformed JSON
      const badJsonRaw = '{"invalid": [1, 2,';
      const malformedRes = await safeFetch(ctx, {
        method: ep.method,
        path: ep.path,
        headers: { ...authHeaders, 'Content-Type': 'application/json' },
        rawBody: badJsonRaw,
      });

      if (malformedRes.status >= 500) {
        findings.push({
          id: 'DYN-004',
          title: `Unhandled server crash (HTTP ${malformedRes.status}) on malformed JSON`,
          severity: 'HIGH',
          category: 'Validation & Payments',
          location: `${ep.method} ${ep.path}`,
          evidence: `HTTP ${malformedRes.status} on malformed JSON — ${truncateEvidence(malformedRes.bodyText)}`,
          reproduction: buildCurlCommand({
            method: ep.method,
            url,
            headers: { 'Content-Type': 'application/json' },
            authEnvVar: userA?.envVarName,
            authStrategy: ctx.config.dynamic.auth?.strategy,
            body: badJsonRaw,
          }),
          whyItMatters:
            'Crashing with HTTP 500 on malformed JSON can expose stack traces, pollute error monitoring, and allow trivial denial-of-service against request parsers.',
          howToFix:
            'Add a JSON body-parsing error handler that returns HTTP 400 Bad Request with a clean generic message when incoming JSON is invalid.\n\n' +
            `AI Fix Prompt: "Add error-handling middleware so malformed JSON sent to ${ep.method} ${ep.path} returns HTTP 400 with a clean JSON error instead of HTTP 500."`,
        });
      }

      // 2. Negative financial / quantity values
      const negativeBody: Record<string, unknown> = { ...ep.sampleValidBody };
      let mutatedNumeric = false;
      for (const [k, v] of Object.entries(negativeBody)) {
        if (typeof v === 'number') {
          negativeBody[k] = -Math.abs(v || 5);
          mutatedNumeric = true;
        }
      }
      if (!mutatedNumeric) {
        negativeBody.quantity = -5;
        negativeBody.amount = -100;
      }

      const negRes = await safeFetch(ctx, {
        method: ep.method,
        path: ep.path,
        headers: authHeaders,
        body: negativeBody,
      });

      if ((negRes.status >= 200 && negRes.status < 300) || negRes.status >= 500) {
        findings.push({
          id: 'DYN-004',
          title:
            negRes.status >= 500
              ? `Server crash (HTTP ${negRes.status}) on negative numeric input`
              : `Endpoint accepted negative numeric/quantity values (HTTP ${negRes.status})`,
          severity: 'HIGH',
          category: 'Validation & Payments',
          location: `${ep.method} ${ep.path}`,
          evidence: `Sent ${JSON.stringify(negativeBody)} -> HTTP ${negRes.status}: ${truncateEvidence(negRes.bodyText)}`,
          reproduction: buildCurlCommand({
            method: ep.method,
            url,
            headers: { 'Content-Type': 'application/json' },
            authEnvVar: userA?.envVarName,
            authStrategy: ctx.config.dynamic.auth?.strategy,
            body: JSON.stringify(negativeBody),
          }),
          whyItMatters:
            'Accepting negative quantities or amounts can invert payment totals, credit an attacker’s wallet instead of charging them, or corrupt inventory and accounting records.',
          howToFix:
            'Validate all quantity, price, and amount fields with positive bounds (e.g., `z.number().int().positive()`) and return HTTP 400/422 for non-positive values.\n\n' +
            `AI Fix Prompt: "Validate numeric inputs on ${ep.method} ${ep.path} to require positive numbers (e.g., quantity >= 1, amount > 0) and return HTTP 400 when violated."`,
        });
      }

      // 3. Wrong data types & oversized string (10KB)
      const oversizedBody: Record<string, unknown> = {};
      for (const key of Object.keys(ep.sampleValidBody)) {
        oversizedBody[key] = 'A'.repeat(10 * 1024);
      }
      if (Object.keys(oversizedBody).length === 0) {
        oversizedBody.input = 'A'.repeat(10 * 1024);
      }

      const overRes = await safeFetch(ctx, {
        method: ep.method,
        path: ep.path,
        headers: authHeaders,
        body: oversizedBody,
      });

      if (overRes.status >= 500) {
        findings.push({
          id: 'DYN-004',
          title: `Server crash (HTTP ${overRes.status}) on oversized/wrong-type payload`,
          severity: 'HIGH',
          category: 'Validation & Payments',
          location: `${ep.method} ${ep.path}`,
          evidence: `Sent 10KB string payload -> HTTP ${overRes.status}: ${truncateEvidence(overRes.bodyText)}`,
          reproduction: `Send a 10KB string payload to ${ep.method} ${url} and observe HTTP ${overRes.status}.`,
          whyItMatters:
            'Failing to validate types and maximum string lengths allows malformed inputs to crash database writes or exhaust server memory.',
          howToFix:
            'Enforce strict type and `.max()` length constraints in your input schema and return HTTP 400/422 when exceeded.\n\n' +
            `AI Fix Prompt: "Add strict type checks and maximum string length limits to ${ep.method} ${ep.path} so oversized or wrong-type payloads return HTTP 400."`,
        });
      }
    }

    return { findings };
  });
}
