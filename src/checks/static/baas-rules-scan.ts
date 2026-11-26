import path from 'node:path';
import type { Finding, ModuleResult } from '../../types.js';
import { runStaticModule, type StaticScanContext } from './utils.js';

const FIRESTORE_OPEN_RULE_REGEX =
  /allow\s+(?:read\s*,\s*write|write\s*,\s*read|write|read)\s*:\s*if\s+true\b/i;

const CREATE_TABLE_REGEX =
  /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:["`]?[\w]+["`]?\.)?["`]?([\w]+)["`]?/gi;

export async function runBaasRulesScan(ctx: StaticScanContext): Promise<ModuleResult> {
  return runStaticModule('STAT-007', 'BaaS Security Rules (Firestore / Supabase RLS)', () => {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      const baseName = path.posix.basename(file.relPath).toLowerCase();

      // 1. Firestore / Firebase Storage open rules
      if (baseName === 'firestore.rules' || baseName === 'storage.rules') {
        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i];
          if (!FIRESTORE_OPEN_RULE_REGEX.test(line)) continue;

          const lineNum = i + 1;
          findings.push({
            id: 'STAT-007',
            title: `Overly permissive Firebase rule in ${baseName}`,
            severity: 'CRITICAL',
            category: 'Auth & Access Control',
            location: `${file.relPath}:${lineNum}`,
            evidence: line.trim().slice(0, 180),
            reproduction: `Inspect ${file.relPath} at line ${lineNum} — rule grants unconditional access via "if true".`,
            whyItMatters:
              'Setting `allow read, write: if true;` in Firebase security rules exposes your entire database or storage bucket to anyone on the internet without authentication, allowing mass data theft or deletion.',
            howToFix:
              'Replace `if true` with explicit authentication and ownership checks such as `if request.auth != null && request.auth.uid == resource.data.userId;`.\n\n' +
              `AI Fix Prompt: "Lock down the Firebase rule at ${file.relPath}:${lineNum} so only authenticated owners (request.auth != null && request.auth.uid == userId) can read or write their own documents."`,
          });
        }
      }

      // 2. Supabase SQL migrations creating tables without ENABLE ROW LEVEL SECURITY
      const isSupabaseSql =
        file.relPath.toLowerCase().endsWith('.sql') &&
        (file.relPath.toLowerCase().includes('supabase') ||
          ctx.stack.databases.includes('supabase'));

      if (isSupabaseSql) {
        CREATE_TABLE_REGEX.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = CREATE_TABLE_REGEX.exec(file.content)) !== null) {
          const tableName = match[1];
          const lineNum = file.content.slice(0, match.index).split(/\r?\n/).length;

          const rlsRegex = new RegExp(
            `ALTER\\s+TABLE\\s+(?:["\`]?[\\w]+["\`]?\\.)?["\`]?${tableName}["\`]?\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`,
            'i',
          );

          if (!rlsRegex.test(file.content)) {
            findings.push({
              id: 'STAT-007',
              title: `Supabase table "${tableName}" created without Row Level Security (RLS)`,
              severity: 'CRITICAL',
              category: 'Auth & Access Control',
              location: `${file.relPath}:${lineNum}`,
              evidence: file.lines[lineNum - 1]?.trim().slice(0, 180) ?? match[0],
              reproduction: `Inspect ${file.relPath}:${lineNum} — no "ALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY" statement found.`,
              whyItMatters:
                'Supabase exposes public schema tables directly via its PostgREST API using the anon key. Any table created without Row Level Security enabled can be read, modified, or wiped by any anonymous client.',
              howToFix:
                `Add \`ALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY;\` and define explicit \`CREATE POLICY\` rules restricting access to \`auth.uid()\`.\n\n` +
                `AI Fix Prompt: "Enable Row Level Security on table '${tableName}' in ${file.relPath} and add least-privilege SELECT/INSERT/UPDATE/DELETE policies scoped to auth.uid()."`,
            });
          }
        }
      }
    }

    return findings;
  });
}
