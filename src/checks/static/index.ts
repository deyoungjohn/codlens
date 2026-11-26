import type { CodlensConfig, DetectedStack, ModuleResult } from '../../types.js';
import { runAuthRoutesScan } from './auth-routes.js';
import { runBaasRulesScan } from './baas-rules-scan.js';
import { runDepsAudit } from './deps-audit.js';
import { runPaymentScan } from './payment-scan.js';
import { runSafeguardsScan } from './safeguards-scan.js';
import { runSecretsScan } from './secrets-scan.js';
import { runSqlCmdScan } from './sql-cmd-scan.js';
import { collectStaticFiles, type StaticScanContext } from './utils.js';
import { runValidationScan } from './validation-scan.js';

export interface StaticAuditOptions {
  skipDepsAudit?: boolean;
  includeTests?: boolean;
}

/**
 * Executes the full static audit suite (STAT-001 through STAT-007 + deps-audit)
 * using a single read-only file walk of the target repository.
 */
export async function runStaticAudit(
  config: CodlensConfig,
  stack: DetectedStack,
  options: StaticAuditOptions = {},
): Promise<ModuleResult[]> {
  const files = await collectStaticFiles(config.targetDir, config.static.ignorePaths);
  const ctx: StaticScanContext = {
    targetDir: config.targetDir,
    config,
    stack,
    files,
    includeTests: options.includeTests ?? false,
  };

  const results: ModuleResult[] = await Promise.all([
    runSecretsScan(ctx),
    runSqlCmdScan(ctx),
    runAuthRoutesScan(ctx),
    runPaymentScan(ctx),
    runValidationScan(ctx),
    runSafeguardsScan(ctx),
    runBaasRulesScan(ctx),
  ]);

  if (!options.skipDepsAudit) {
    results.push(await runDepsAudit(ctx));
  }

  return results;
}
