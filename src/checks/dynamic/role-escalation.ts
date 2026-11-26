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

const ESCALATION_PAYLOAD = {
  role: 'admin',
  isAdmin: true,
  plan: 'pro',
  balance: 999999,
};

function hasPrivilegedFieldsSet(data: unknown): string[] {
  if (!data || typeof data !== 'object') return [];
  const record = data as Record<string, unknown>;
  const nested =
    record.user && typeof record.user === 'object'
      ? (record.user as Record<string, unknown>)
      : record.profile && typeof record.profile === 'object'
        ? (record.profile as Record<string, unknown>)
        : record;

  const escalated: string[] = [];
  if (typeof nested.role === 'string' && nested.role.toLowerCase() === 'admin') {
    escalated.push('role="admin"');
  }
  if (nested.isAdmin === true) {
    escalated.push('isAdmin=true');
  }
  if (typeof nested.plan === 'string' && nested.plan.toLowerCase() === 'pro') {
    escalated.push('plan="pro"');
  }
  if (typeof nested.balance === 'number' && nested.balance >= 999999) {
    escalated.push(`balance=${nested.balance}`);
  }
  return escalated;
}

export async function runRoleEscalationProbe(ctx: DynamicContext): Promise<ModuleResult> {
  return runDynamicModule('DYN-003', 'Mass Assignment & Role Escalation', async () => {
    const endpoint = ctx.config.dynamic.profileUpdateEndpoint;
    if (!endpoint) {
      return {
        findings: [],
        skippedReason: 'No profileUpdateEndpoint configured in codlens.config.json.',
      };
    }

    const userA = resolveUserAuth(ctx.config.dynamic.auth, 'userA');
    if (!userA) {
      return {
        findings: [],
        skippedReason:
          'User A auth token is not available (set dynamic.auth.userA.tokenEnvVar).',
      };
    }

    const findings: Finding[] = [];
    const res = await safeFetch(ctx, {
      method: endpoint.method,
      path: endpoint.path,
      headers: userA.headers,
      body: ESCALATION_PAYLOAD,
    });

    let escalatedFields = hasPrivilegedFieldsSet(res.bodyJson);

    // Re-fetch profile via GET to verify persisted state
    if (escalatedFields.length === 0) {
      const getRes = await safeFetch(ctx, {
        method: 'GET',
        path: endpoint.path,
        headers: userA.headers,
      }).catch(() => null);
      if (getRes && getRes.status >= 200 && getRes.status < 300) {
        escalatedFields = hasPrivilegedFieldsSet(getRes.bodyJson);
      }
    }

    if (escalatedFields.length > 0) {
      const url = joinUrl(ctx.baseUrl, endpoint.path);
      const curl = buildCurlCommand({
        method: endpoint.method,
        url,
        headers: { 'Content-Type': 'application/json' },
        authEnvVar: userA.envVarName,
        authStrategy: ctx.config.dynamic.auth?.strategy,
        body: JSON.stringify(ESCALATION_PAYLOAD),
      });

      findings.push({
        id: 'DYN-003',
        title: `Mass assignment / privilege escalation on ${endpoint.method} ${endpoint.path}`,
        severity: 'CRITICAL',
        category: 'Auth & Access Control',
        location: `${endpoint.method} ${endpoint.path}`,
        evidence: `HTTP ${res.status} — Privileged fields accepted/persisted: ${escalatedFields.join(', ')}. Body: ${truncateEvidence(res.bodyText)}`,
        reproduction: curl,
        whyItMatters:
          'Passing `req.body` directly into a user update lets any normal user promote themselves to admin, unlock paid plans, or inflate their account balance with a single API call.',
        howToFix:
          'Explicitly pick only safe, user-editable fields (e.g., `name`, `avatarUrl`) using a strict Zod/Pydantic allowlist schema and strip or reject privileged fields like `role`, `isAdmin`, `plan`, and `balance`.\n\n' +
          `AI Fix Prompt: "Prevent mass assignment on ${endpoint.method} ${endpoint.path} by validating req.body against a strict allowlist schema (only safe profile fields) and ignoring or rejecting role, isAdmin, plan, and balance."`,
      });
    }

    return { findings };
  });
}
