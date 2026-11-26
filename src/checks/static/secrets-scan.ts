import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import type { Finding, ModuleResult } from '../../types.js';
import {
  isCommentLine,
  maskSecret,
  redactLine,
  runStaticModule,
  shannonEntropy,
  type StaticScanContext,
} from './utils.js';

const execFileAsync = promisify(execFile);

interface SecretPattern {
  name: string;
  regex: RegExp;
  captureGroup?: number;
}

const SECRET_PATTERNS: SecretPattern[] = [
  { name: 'Stripe/Paystack Live Secret Key', regex: /\b(sk_live_[A-Za-z0-9]{12,})\b/, captureGroup: 1 },
  { name: 'Stripe/Paystack Test Secret Key', regex: /\b(sk_test_[A-Za-z0-9]{12,})\b/, captureGroup: 1 },
  { name: 'Anthropic API Key', regex: /\b(sk-ant-[A-Za-z0-9_-]{16,})\b/, captureGroup: 1 },
  { name: 'OpenAI API Key', regex: /\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b/, captureGroup: 1 },
  { name: 'Google API Key', regex: /\b(AIza[0-9A-Za-z_-]{20,})\b/, captureGroup: 1 },
  { name: 'GitHub Personal Access Token', regex: /\b(gh[pousr]_[A-Za-z0-9]{20,})\b/, captureGroup: 1 },
  {
    name: 'Database Connection String with Password',
    regex: /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s"']+):([^@\s"']{4,})@/i,
    captureGroup: 2,
  },
  {
    name: 'Hardcoded JWT or App Secret',
    regex:
      /\b(?:JWT_SECRET|SESSION_SECRET|WEBHOOK_SECRET|PAYSTACK_SECRET(?:_KEY)?|STRIPE_SECRET(?:_KEY)?|SUPABASE_SERVICE_ROLE_KEY|PRIVATE_KEY|API_SECRET)\b\s*[:=]\s*['"`]([^'"`\s]{8,})['"`]/i,
    captureGroup: 1,
  },
];

const PUBLIC_SECRET_ENV_REGEX =
  /\b((?:NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|API_KEY|TOKEN|PASSWORD)[A-Z0-9_]*)\b/g;

const HIGH_ENTROPY_ASSIGNMENT_REGEX =
  /\b(?:secret|token|apikey|api_key|private_key|auth_secret|signing_key)\b\s*[:=]\s*['"`]([A-Za-z0-9+/=_-]{24,})['"`]/i;

const PLACEHOLDER_HINTS = /example|placeholder|changeme|your[_-]|dummy|replace[_-]|xxx|0000|process\.env|os\.environ/i;

async function checkEnvGitHygiene(ctx: StaticScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  const envFile = ctx.files.find((f) => path.posix.basename(f.relPath) === '.env');

  // Check if .env is tracked in git
  if (ctx.stack.hasGit) {
    try {
      const { stdout } = await execFileAsync('git', ['ls-files', '--', '.env', '**/.env'], {
        cwd: ctx.targetDir,
        timeout: 5000,
      });
      const tracked = stdout
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);
      for (const trackedEnv of tracked) {
        findings.push({
          id: 'STAT-001',
          title: 'Environment file (.env) is tracked in Git',
          severity: 'CRITICAL',
          category: 'Secrets',
          location: `${trackedEnv}:1`,
          evidence: `git ls-files reports "${trackedEnv}" is tracked in version control.`,
          reproduction: `cd "${ctx.targetDir}" && git ls-files -- "${trackedEnv}"`,
          whyItMatters:
            'Committing a .env file permanently embeds API keys, database passwords, and signing secrets in Git history. Anyone with repository access—or automated scanners if the repo is ever made public—can steal those credentials.',
          howToFix:
            `Remove ${trackedEnv} from Git tracking (\`git rm --cached ${trackedEnv}\`), add \`.env\` to \`.gitignore\`, and rotate all exposed secrets.\n\n` +
            `AI Fix Prompt: "Add .env and .env.* (except .env.example) to .gitignore and provide a .env.example template with placeholder values only."`,
        });
      }
    } catch {
      // git not available or not a valid git worktree
    }
  }

  // Check if .env exists while missing from .gitignore
  if (envFile) {
    const gitignorePath = path.join(ctx.targetDir, '.gitignore');
    let gitignoreContent = '';
    try {
      gitignoreContent = await fs.readFile(gitignorePath, 'utf8');
    } catch {
      // no .gitignore
    }

    const ignoresEnv = gitignoreContent
      .split(/\r?\n/)
      .some((line) => /^\s*\.env(?:\*|\.\*)?\s*$/.test(line));

    if (!ignoresEnv) {
      findings.push({
        id: 'STAT-001',
        title: '.env file exists but is missing from .gitignore',
        severity: 'CRITICAL',
        category: 'Secrets',
        location: `.gitignore:1`,
        evidence: `Found "${envFile.relPath}" without a matching ".env" entry in .gitignore.`,
        reproduction: `Inspect "${path.join(ctx.targetDir, '.gitignore')}" for a ".env" rule.`,
        whyItMatters:
          'Without .env listed in .gitignore, a single `git add .` can accidentally commit live credentials and database passwords to your repository.',
        howToFix:
          'Add `.env` and `.env.*` (excluding `.env.example`) to `.gitignore` immediately.\n\n' +
          'AI Fix Prompt: "Update .gitignore to ignore .env, .env.local, and .env.*.local while keeping .env.example tracked."',
      });
    }
  }

  return findings;
}

export async function runSecretsScan(ctx: StaticScanContext): Promise<ModuleResult> {
  return runStaticModule('STAT-001', 'Secret & Key Leakage', async () => {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    const addFinding = (dedupeKey: string, finding: Finding): void => {
      if (seen.has(dedupeKey)) return;
      seen.add(dedupeKey);
      findings.push(finding);
    };

    for (const file of ctx.files) {
      const baseName = path.posix.basename(file.relPath);
      if (baseName === 'package-lock.json' || baseName === 'yarn.lock' || baseName === 'pnpm-lock.yaml') {
        continue;
      }
      // Do not treat .env.example as leaked secrets unless it has a real key prefix
      const isEnvFile = baseName === '.env' || baseName.startsWith('.env.');

      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const lineNum = i + 1;

        if (!isEnvFile && isCommentLine(line)) continue;

        // 1. Check client-exposed public env vars containing secret keywords
        PUBLIC_SECRET_ENV_REGEX.lastIndex = 0;
        let pubMatch: RegExpExecArray | null;
        while ((pubMatch = PUBLIC_SECRET_ENV_REGEX.exec(line)) !== null) {
          const varName = pubMatch[1];
          // Mask any value assigned on the same line
          const eqIdx = line.indexOf('=');
          let safeEvidence = line.trim().slice(0, 160);
          if (eqIdx !== -1) {
            const rhs = line.slice(eqIdx + 1).trim().replace(/^['"`]|['"`];?$/g, '');
            if (rhs.length > 4) {
              safeEvidence = redactLine(line, rhs);
            }
          }
          addFinding(`pub:${file.relPath}:${lineNum}:${varName}`, {
            id: 'STAT-001',
            title: `Secret variable exposed to browser bundle via ${varName}`,
            severity: 'CRITICAL',
            category: 'Secrets',
            location: `${file.relPath}:${lineNum}`,
            evidence: safeEvidence,
            reproduction: `Inspect ${file.relPath} at line ${lineNum} for "${varName}".`,
            whyItMatters:
              'Environment variables prefixed with NEXT_PUBLIC_, VITE_, or REACT_APP_ are inlined into client-side JavaScript bundles. Any user can open browser DevTools and extract the secret key.',
            howToFix:
              `Rename "${varName}" to remove the public prefix (e.g., server-only env var) and move all logic that uses it into a server-side API route or server action.\n\n` +
              `AI Fix Prompt: "Remove the public prefix from ${varName} in ${file.relPath}:${lineNum}, keep the key strictly server-side, and proxy any required operation through an authenticated backend endpoint."`,
          });
        }

        // Skip raw secret scanning inside .env itself (its risk is git tracking, handled separately)
        if (isEnvFile) continue;

        // 2. Known secret regex patterns
        let matchedKnown = false;
        for (const pattern of SECRET_PATTERNS) {
          const match = pattern.regex.exec(line);
          if (!match) continue;

          const secretVal = match[pattern.captureGroup ?? 0];
          if (!secretVal || PLACEHOLDER_HINTS.test(secretVal)) continue;

          matchedKnown = true;
          addFinding(`pat:${file.relPath}:${lineNum}:${pattern.name}`, {
            id: 'STAT-001',
            title: `Hardcoded ${pattern.name} detected`,
            severity: 'CRITICAL',
            category: 'Secrets',
            location: `${file.relPath}:${lineNum}`,
            evidence: redactLine(line, secretVal),
            reproduction: `Inspect ${file.relPath} at line ${lineNum} (masked value: ${maskSecret(secretVal)}).`,
            whyItMatters:
              'Hardcoded credentials in source code can be stolen by anyone with access to the repository, build artifacts, or logs. Attackers routinely automate scanning for leaked API keys and database passwords.',
            howToFix:
              `Move this secret out of source code into an environment variable (loaded via \`process.env\` / \`os.environ\`), add \`.env\` to \`.gitignore\`, and rotate the exposed credential.\n\n` +
              `AI Fix Prompt: "Replace the hardcoded ${pattern.name} at ${file.relPath}:${lineNum} with a required environment variable lookup that throws a clear startup error if missing."`,
          });
        }

        // 3. High-entropy secret assignment fallback
        if (!matchedKnown) {
          const entropyMatch = HIGH_ENTROPY_ASSIGNMENT_REGEX.exec(line);
          if (entropyMatch) {
            const candidate = entropyMatch[1];
            if (!PLACEHOLDER_HINTS.test(candidate) && shannonEntropy(candidate) >= 3.8) {
              addFinding(`ent:${file.relPath}:${lineNum}`, {
                id: 'STAT-001',
                title: 'High-entropy hardcoded secret detected',
                severity: 'CRITICAL',
                category: 'Secrets',
                location: `${file.relPath}:${lineNum}`,
                evidence: redactLine(line, candidate),
                reproduction: `Inspect ${file.relPath} at line ${lineNum} (masked value: ${maskSecret(candidate)}).`,
                whyItMatters:
                  'A high-entropy string assigned to a secret or token variable in source code is likely a real credential. Leaving it in code risks unauthorized access if the codebase is shared or leaked.',
                howToFix:
                  `Load this value from an environment variable instead of hardcoding it in ${file.relPath}, and rotate the key if it was ever used in production.\n\n` +
                  `AI Fix Prompt: "Move the hardcoded secret at ${file.relPath}:${lineNum} into an environment variable and fail fast on startup if it is undefined."`,
              });
            }
          }
        }
      }
    }

    const envFindings = await checkEnvGitHygiene(ctx);
    for (const f of envFindings) {
      addFinding(`env:${f.location}:${f.title}`, f);
    }

    return findings;
  });
}
