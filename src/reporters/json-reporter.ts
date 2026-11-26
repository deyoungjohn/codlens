import fs from 'node:fs/promises';
import path from 'node:path';
import type { AuditReport } from '../types.js';

export async function writeJsonReport(reportDir: string, report: AuditReport): Promise<string> {
  await fs.mkdir(reportDir, { recursive: true });
  const filePath = path.join(reportDir, 'codlens-report.json');
  await fs.writeFile(filePath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  return filePath;
}
