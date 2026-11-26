import type { AuditReport } from '../types.js';

export function formatConsoleSummary(
  report: AuditReport,
  paths?: { jsonPath?: string; mdPath?: string },
): string {
  const { summary } = report;
  const lines: string[] = [
    '',
    `================ CODLENS AUDIT SUMMARY ================`,
    `Project:  ${report.projectName}`,
    `Target:   ${report.targetDir}`,
    ...(report.baseUrl ? [`URL:      ${report.baseUrl}`] : [`Mode:     Static Only`]),
    `Verdict:  ${summary.verdict} (exit code ${summary.exitCode})`,
    `-------------------------------------------------------`,
    `Findings: CRITICAL=${summary.bySeverity.CRITICAL}  HIGH=${summary.bySeverity.HIGH}  MEDIUM=${summary.bySeverity.MEDIUM}  LOW=${summary.bySeverity.LOW}  INFO=${summary.bySeverity.INFO}`,
    `-------------------------------------------------------`,
  ];

  for (const mod of report.modules) {
    const idCol = mod.moduleId.padEnd(10);
    const kindCol = mod.kind.padEnd(8);
    const statusCol = mod.status.toUpperCase().padEnd(8);
    const countCol = `${mod.findings.length} finding(s)`.padEnd(14);
    lines.push(`  ${idCol} ${kindCol} ${statusCol} ${countCol} ${mod.moduleName}`);
  }

  lines.push(`=======================================================`);

  if (paths?.mdPath || paths?.jsonPath) {
    if (paths.mdPath) lines.push(`Markdown Report: ${paths.mdPath}`);
    if (paths.jsonPath) lines.push(`JSON Report:     ${paths.jsonPath}`);
  }

  return `${lines.join('\n')}\n`;
}

export function printConsoleSummary(
  report: AuditReport,
  paths?: { jsonPath?: string; mdPath?: string },
): void {
  console.log(formatConsoleSummary(report, paths));
}
