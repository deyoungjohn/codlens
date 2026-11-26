import type { Finding, ModuleResult } from '../../types.js';
import { isCodeFile, isCommentLine, runStaticModule, type StaticScanContext } from './utils.js';

interface InjectionRule {
  title: string;
  regex: RegExp;
  whyItMatters: string;
  howToFix: string;
}

const INJECTION_RULES: InjectionRule[] = [
  {
    title: 'Potential SQL injection via string interpolation or concatenation',
    regex:
      /(?:\.(?:query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|['"][^'"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^'"]*['"]\s*\+|f['"][^'"]*\{[^}]+\}[^'"]*['"])|\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^;\n]*(?:\$\{[^}]+\}|['"]\s*\+\s*[a-zA-Z_$]))/i,
    whyItMatters:
      'Interpolating user-controlled input directly into a SQL string lets an attacker alter the query structure, bypass authentication, dump the entire database, or delete records.',
    howToFix:
      'Use parameterized queries / prepared statements (e.g., `$1`, `?` placeholders, or ORM query builders like Prisma/Drizzle) so user input is never parsed as SQL.\n\n' +
      'AI Fix Prompt: "Refactor the SQL query at this location to use parameterized placeholders instead of string interpolation or concatenation."',
  },
  {
    title: 'Potential command injection via shell execution with dynamic input',
    regex:
      /\b(?:exec|execSync|spawn|spawnSync|os\.system|subprocess\.(?:run|Popen|call))\s*\([^)]*(?:\$\{[^}]+\}|['"]\s*\+|f['"][^'"]*\{[^}]+\}|shell\s*[:=]\s*[Tt]rue)/,
    whyItMatters:
      'Passing untrusted input into a shell command allows attackers to chain arbitrary OS commands (e.g., `; rm -rf /` or exfiltrating environment variables and secrets).',
    howToFix:
      'Use `execFile` / `spawn` with `shell: false` and pass arguments as a validated array, avoiding shell string interpolation entirely.\n\n' +
      'AI Fix Prompt: "Replace the shell command execution at this location with execFile/spawn using an explicit argument array and strict input allowlisting."',
  },
  {
    title: 'Unsafe dynamic code evaluation (eval / new Function)',
    regex: /\b(?:eval\s*\(|new\s+Function\s*\()/,
    whyItMatters:
      'Executing dynamically constructed strings as code enables arbitrary Remote Code Execution (RCE) on the server or Cross-Site Scripting (XSS) in the browser if any part of the input is user-controlled.',
    howToFix:
      'Remove `eval()` / `new Function()` and replace with structured parsing (e.g., `JSON.parse`, explicit dispatch tables, or a safe expression parser).\n\n' +
      'AI Fix Prompt: "Eliminate eval()/new Function() at this location and replace it with a safe, deterministic alternative."',
  },
  {
    title: 'Potential XSS via dangerouslySetInnerHTML',
    regex: /\bdangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/,
    whyItMatters:
      'Rendering unsanitized HTML with dangerouslySetInnerHTML allows attackers to inject malicious JavaScript (XSS) that steals user sessions, cookies, or tokens.',
    howToFix:
      'Render plain text via JSX whenever possible. If rich HTML is strictly required, sanitize it first with a well-tested library such as DOMPurify.\n\n' +
      'AI Fix Prompt: "Sanitize the HTML passed to dangerouslySetInnerHTML at this location using DOMPurify, or replace it with safe JSX rendering."',
  },
];

export async function runSqlCmdScan(ctx: StaticScanContext): Promise<ModuleResult> {
  return runStaticModule('STAT-002', 'Injection Risks (SQL / Command / XSS)', () => {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      if (!isCodeFile(file.relPath)) continue;

      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const lineNum = i + 1;
        if (isCommentLine(line)) continue;

        for (const rule of INJECTION_RULES) {
          if (!rule.regex.test(line)) continue;

          // Allow dangerouslySetInnerHTML if DOMPurify.sanitize is directly on the same line
          if (
            rule.title.includes('dangerouslySetInnerHTML') &&
            /DOMPurify\.sanitize\s*\(/i.test(line)
          ) {
            continue;
          }

          findings.push({
            id: 'STAT-002',
            title: rule.title,
            severity: 'CRITICAL',
            category: 'Injection',
            location: `${file.relPath}:${lineNum}`,
            evidence: line.trim().slice(0, 200),
            reproduction: `Inspect ${file.relPath} at line ${lineNum} to verify whether untrusted input reaches this sink.`,
            whyItMatters: rule.whyItMatters,
            howToFix: rule.howToFix,
          });
        }
      }
    }

    return findings;
  });
}
