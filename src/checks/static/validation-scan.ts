import type { Finding, ModuleResult } from '../../types.js';
import { isCodeFile, runStaticModule, type StaticScanContext } from './utils.js';

const REQUEST_BODY_READ_REGEX =
  /\b(?:req\.body|await\s+req(?:uest)?\.json\(\)|request\.get_json\(\))/;

const DB_WRITE_SIGNAL_REGEX =
  /\.(?:create|update|upsert|insert|insertOne|insertMany|updateOne|save|findByIdAndUpdate|push)\s*\(|Object\.assign\s*\(/;

const VALIDATION_SIGNAL_REGEX =
  /\b(?:zod|z\.object|safeParse|\.parse\(|joi\.|yup\.|valibot|class-validator|BaseModel|pydantic|express-validator|Number\.isInteger|typeof\s+.*===\s*['"](?:string|number|boolean)['"])\b/i;

export async function runValidationScan(ctx: StaticScanContext): Promise<ModuleResult> {
  return runStaticModule('STAT-005', 'Missing Input Validation', () => {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      if (!isCodeFile(file.relPath)) continue;

      const fileHasSchemaLib = /\b(?:from\s+['"](?:zod|joi|yup|valibot)['"]|require\(['"](?:zod|joi|yup)['"]\)|from\s+pydantic\s+import)\b/.test(
        file.content,
      );

      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        if (!REQUEST_BODY_READ_REGEX.test(line)) continue;

        const lineNum = i + 1;
        const windowText = file.lines.slice(Math.max(0, i - 3), i + 25).join('\n');

        // Only flag when the handler writes data (DB or in-memory store mutation) without validation
        if (!DB_WRITE_SIGNAL_REGEX.test(windowText)) continue;
        if (VALIDATION_SIGNAL_REGEX.test(windowText)) continue;
        if (fileHasSchemaLib && /\.(?:parse|safeParse|validate)\s*\(/.test(windowText)) continue;

        findings.push({
          id: 'STAT-005',
          title: 'Request body passed to data write without schema validation',
          severity: 'MEDIUM',
          category: 'Validation & Payments',
          location: `${file.relPath}:${lineNum}`,
          evidence: line.trim().slice(0, 180),
          reproduction: `Inspect ${file.relPath}:${lineNum} — request body is consumed directly into a write operation without Zod/Joi/Yup/Pydantic or explicit type/range checks.`,
          whyItMatters:
            'Writing unvalidated request payloads directly to your database or state store enables mass assignment (e.g., setting `role: "admin"`), crashes from wrong types, and logic bugs like negative quantities.',
          howToFix:
            'Define an explicit allowlist schema (using Zod, Joi, Yup, or Pydantic) with strict types and numeric bounds (e.g., `z.number().int().positive()`), and pass only the validated output to your write operation.\n\n' +
            `AI Fix Prompt: "Add a strict Zod (or Pydantic) validation schema for the request body at ${file.relPath}:${lineNum}, returning HTTP 400 on validation failure and passing only explicitly allowed fields to the database write."`,
        });
      }
    }

    return findings;
  });
}
