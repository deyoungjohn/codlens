import { runDynamicAudit } from '../checks/dynamic/index.js';
import { runStaticAudit } from '../checks/static/index.js';
import {
  ExitCode,
  type AuditReport,
  type AuditSummary,
  type CodlensConfig,
  type Finding,
  type ModuleResult,
  type ReadinessVerdict,
  type SafetyGuardOptions,
  type Severity,
} from '../types.js';
import { detectStack } from './detector.js';

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

export interface RunAuditOptions {
  staticOnly?: boolean;
  baseUrl?: string;
  safety?: SafetyGuardOptions;
  browser?: boolean;
  skipDepsAudit?: boolean;
  timeoutMs?: number;
}

export function computeAuditSummary(findings: Finding[]): AuditSummary {
  const bySeverity: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };

  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  }

  let verdict: ReadinessVerdict;
  let exitCode: (typeof ExitCode)[keyof typeof ExitCode];

  if (bySeverity.CRITICAL > 0) {
    verdict = 'BLOCKED FOR LAUNCH';
    exitCode = ExitCode.AUDIT_FAILED;
  } else if (bySeverity.HIGH > 0) {
    verdict = 'NEEDS HARDENING';
    exitCode = ExitCode.AUDIT_FAILED;
  } else {
    verdict = 'LAUNCH READY WITH NOTES';
    exitCode = ExitCode.PASS;
  }

  return {
    totalFindings: findings.length,
    bySeverity,
    verdict,
    exitCode,
  };
}

export function formatReportTimestamp(date = new Date()): string {
  const pad = (n: number): string => String(n).padStart(2, '0');
  return (
    `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-` +
    `${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`
  );
}

/**
 * Orchestrates stack detection, static checks, and dynamic probes,
 * returning a complete AuditReport with deterministic verdict and exit code.
 */
export async function runAudit(
  config: CodlensConfig,
  options: RunAuditOptions = {},
): Promise<AuditReport> {
  const detectedStack = await detectStack(config.targetDir, {
    ignorePaths: config.static.ignorePaths,
  });

  const modules: ModuleResult[] = [];

  // 1. Static Audit
  const staticResults = await runStaticAudit(config, detectedStack, {
    skipDepsAudit: options.skipDepsAudit,
  });
  modules.push(...staticResults);

  // 2. Dynamic Audit (unless --static-only or disabled)
  const effectiveBaseUrl = options.baseUrl ?? config.baseUrl;
  const shouldRunDynamic = !options.staticOnly && config.dynamic.enabled && Boolean(effectiveBaseUrl);

  if (shouldRunDynamic && effectiveBaseUrl) {
    const dynamicResults = await runDynamicAudit(config, {
      baseUrl: effectiveBaseUrl,
      safety: options.safety,
      browser: options.browser,
      timeoutMs: options.timeoutMs,
    });
    modules.push(...dynamicResults);
  }

  const allFindings = modules
    .flatMap((m) => m.findings)
    .sort((a, b) => {
      const sevDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
      if (sevDiff !== 0) return sevDiff;
      return a.id.localeCompare(b.id);
    });

  const summary = computeAuditSummary(allFindings);

  return {
    tool: 'codlens',
    version: '0.1.0',
    timestamp: new Date().toISOString(),
    projectName: config.projectName,
    targetDir: config.targetDir,
    ...(shouldRunDynamic && effectiveBaseUrl ? { baseUrl: effectiveBaseUrl } : {}),
    detectedStack,
    summary,
    modules,
    findings: allFindings,
  };
}
