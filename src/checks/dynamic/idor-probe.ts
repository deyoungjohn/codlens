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

export async function runIdorProbe(ctx: DynamicContext): Promise<ModuleResult> {
  return runDynamicModule('DYN-002', 'IDOR / Cross-Tenant Access Probe', async () => {
    const targets = ctx.config.dynamic.idorTargets;
    if (targets.length === 0) {
      return {
        findings: [],
        skippedReason: 'No idorTargets configured in codlens.config.json.',
      };
    }

    const userA = resolveUserAuth(ctx.config.dynamic.auth, 'userA');
    if (!userA) {
      return {
        findings: [],
        skippedReason:
          'User A auth token is not available (set the environment variable configured in dynamic.auth.userA.tokenEnvVar).',
      };
    }

    const findings: Finding[] = [];

    for (const target of targets) {
      const resolvedPath = target.pathTemplate.replace(
        /:[a-zA-Z0-9_]+/,
        encodeURIComponent(target.ownerBResourceId),
      );
      const res = await safeFetch(ctx, {
        method: target.method,
        path: resolvedPath,
        headers: userA.headers,
      });

      const url = joinUrl(ctx.baseUrl, resolvedPath);
      const curl = buildCurlCommand({
        method: target.method,
        url,
        authEnvVar: userA.envVarName,
        authStrategy: ctx.config.dynamic.auth?.strategy,
      });

      if (res.status >= 200 && res.status < 300) {
        findings.push({
          id: 'DYN-002',
          title: `Cross-tenant IDOR vulnerability on ${target.method} ${resolvedPath}`,
          severity: 'CRITICAL',
          category: 'Auth & Access Control',
          location: `${target.method} ${resolvedPath}`,
          evidence: `Authenticated as userA, received HTTP ${res.status} for userB resource "${target.ownerBResourceId}" — ${truncateEvidence(res.bodyText)}`,
          reproduction: curl,
          whyItMatters:
            'An Insecure Direct Object Reference (IDOR) lets any logged-in user view, edit, or delete another customer’s private records simply by changing an ID in the URL.',
          howToFix:
            `Always scope database queries and mutations to the authenticated user (e.g., \`WHERE id = $1 AND user_id = req.user.id\`) and return HTTP 403 or 404 when the record does not belong to the caller.\n\n` +
            `AI Fix Prompt: "Fix the IDOR vulnerability on ${target.method} ${target.pathTemplate} by verifying that the target resource's owner ID matches the authenticated user's ID, returning 403 or 404 otherwise."`,
        });
      }
    }

    return { findings };
  });
}
