import fs from 'node:fs/promises';
import path from 'node:path';
import type { AuditReport, Finding, Severity } from '../types.js';

function verdictIcon(verdict: AuditReport['summary']['verdict']): string {
  switch (verdict) {
    case 'BLOCKED FOR LAUNCH':
      return '🔴';
    case 'NEEDS HARDENING':
      return '🟠';
    case 'LAUNCH READY WITH NOTES':
      return '🟢';
  }
}

function severityBadge(sev: Severity): string {
  switch (sev) {
    case 'CRITICAL':
      return '`CRITICAL`';
    case 'HIGH':
      return '`HIGH`';
    case 'MEDIUM':
      return '`MEDIUM`';
    case 'LOW':
      return '`LOW`';
    case 'INFO':
      return '`INFO`';
  }
}

function renderFindingMarkdown(finding: Finding, index: number): string {
  const lines: string[] = [
    `### ${index + 1}. [${finding.id}] ${finding.title}`,
    '',
    `- **Severity:** ${severityBadge(finding.severity)}`,
    `- **Category:** ${finding.category}`,
    `- **Location:** \`${finding.location}\``,
    '',
    '**Evidence (Redacted):**',
    '```text',
    finding.evidence,
    '```',
    '',
    '**How to Reproduce:**',
    '```bash',
    finding.reproduction,
    '```',
    '',
    '**Why It Matters:**',
    finding.whyItMatters,
    '',
    '**How to Fix:**',
    finding.howToFix,
    '',
    '---',
    '',
  ];
  return lines.join('\n');
}

export function renderMarkdownReport(report: AuditReport): string {
  const { summary, detectedStack } = report;
  const lines: string[] = [
    `# Codlens Audit Report — ${report.projectName}`,
    '',
    `## Overall Readiness Verdict: ${verdictIcon(summary.verdict)} **${summary.verdict}**`,
    '',
    `- **Generated:** ${report.timestamp}`,
    `- **Target Directory:** \`${report.targetDir}\``,
    ...(report.baseUrl ? [`- **Target URL:** \`${report.baseUrl}\``] : ['- **Mode:** Static Only']),
    `- **Exit Code:** \`${summary.exitCode}\``,
    '',
    '## Executive Summary',
    '',
    '| Severity | Count |',
    '| :--- | :---: |',
    `| CRITICAL | ${summary.bySeverity.CRITICAL} |`,
    `| HIGH | ${summary.bySeverity.HIGH} |`,
    `| MEDIUM | ${summary.bySeverity.MEDIUM} |`,
    `| LOW | ${summary.bySeverity.LOW} |`,
    `| INFO | ${summary.bySeverity.INFO} |`,
    `| **Total** | **${summary.totalFindings}** |`,
    '',
    '## Detected Stack',
    '',
    `- **Frameworks:** ${detectedStack.frameworks.join(', ') || 'None detected'}`,
    `- **Databases / BaaS:** ${detectedStack.databases.join(', ') || 'None detected'}`,
    `- **Payment Providers:** ${detectedStack.paymentProviders.join(', ') || 'None detected'}`,
    `- **AI / LLM SDKs:** ${detectedStack.aiSdks.join(', ') || 'None detected'}`,
    `- **Languages:** ${detectedStack.languages.join(', ') || 'None detected'}`,
    '',
    '## Module Results',
    '',
    '| Module | Kind | Status | Findings | Duration |',
    '| :--- | :---: | :---: | :---: | :---: |',
  ];

  for (const mod of report.modules) {
    const statusLabel = mod.skippedReason ? `skipped (${mod.skippedReason})` : mod.status;
    lines.push(
      `| \`${mod.moduleId}\` ${mod.moduleName} | ${mod.kind} | ${statusLabel} | ${mod.findings.length} | ${mod.durationMs}ms |`,
    );
  }

  lines.push('', '## Findings & Learning Breakdown', '');

  if (report.findings.length === 0) {
    lines.push(
      'No security or production-readiness issues were flagged by the configured checks.',
      '',
    );
  } else {
    for (let i = 0; i < report.findings.length; i++) {
      lines.push(renderFindingMarkdown(report.findings[i], i));
    }
  }

  return `${lines.join('\n').trimEnd()}\n`;
}

export async function writeMarkdownReport(reportDir: string, report: AuditReport): Promise<string> {
  await fs.mkdir(reportDir, { recursive: true });
  const filePath = path.join(reportDir, 'CODLENS_REPORT.md');
  await fs.writeFile(filePath, renderMarkdownReport(report), 'utf8');
  return filePath;
}
