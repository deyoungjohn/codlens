import { assertSafeTargetUrl } from '../../core/safety-guard.js';
import type { CodlensConfig, ModuleResult, SafetyGuardOptions } from '../../types.js';
import { runAuthBypassProbe } from './auth-bypass.js';
import { runBrowserProbe } from './browser-probe.js';
import { runErrorLeakageProbe } from './error-leakage.js';
import { runHeadersCorsProbe } from './headers-cors.js';
import type { DynamicContext } from './http-client.js';
import { runIdorProbe } from './idor-probe.js';
import { runInputFuzzerProbe } from './input-fuzzer.js';
import { runRateLimitProbe } from './rate-limit.js';
import { runRoleEscalationProbe } from './role-escalation.js';
import { runWebhookProbe } from './webhook-probe.js';

export interface DynamicAuditOptions {
  baseUrl?: string;
  safety?: SafetyGuardOptions;
  browser?: boolean;
  timeoutMs?: number;
  maxRetries?: number;
}

/**
 * Verifies the target server is reachable before running dynamic probes.
 */
async function checkServerReachable(baseUrl: string, timeoutMs: number): Promise<void> {
  try {
    await fetch(baseUrl, {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Target server at ${baseUrl} is unreachable: ${msg}`);
  }
}

/**
 * Runs the full dynamic audit suite (DYN-001 through DYN-008, plus optional --browser).
 */
export async function runDynamicAudit(
  config: CodlensConfig,
  options: DynamicAuditOptions = {},
): Promise<ModuleResult[]> {
  const baseUrl = options.baseUrl ?? config.baseUrl;
  if (!baseUrl) {
    throw new Error('Dynamic audit enabled but no baseUrl was provided in config or --base-url.');
  }

  const safety: SafetyGuardOptions = options.safety ?? {};
  assertSafeTargetUrl(baseUrl, safety);

  const timeoutMs = options.timeoutMs ?? 5000;
  await checkServerReachable(baseUrl, timeoutMs);

  const ctx: DynamicContext = {
    baseUrl,
    config,
    safety,
    timeoutMs,
    maxRetries: options.maxRetries ?? 1,
  };

  const results: ModuleResult[] = [];
  results.push(await runAuthBypassProbe(ctx));
  results.push(await runIdorProbe(ctx));
  results.push(await runRoleEscalationProbe(ctx));
  results.push(await runInputFuzzerProbe(ctx));
  results.push(await runWebhookProbe(ctx));
  results.push(await runErrorLeakageProbe(ctx));
  results.push(await runRateLimitProbe(ctx));
  results.push(await runHeadersCorsProbe(ctx));

  if (options.browser) {
    results.push(await runBrowserProbe(ctx));
  }

  return results;
}
