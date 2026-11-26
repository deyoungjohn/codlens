import type { Finding, ModuleResult } from '../../types.js';
import { isCodeFile, runStaticModule, type StaticScanContext } from './utils.js';

const UPLOAD_SIGNAL_REGEX =
  /\b(?:multer\s*\(|formidable\s*\(|busboy\s*\(|UploadFile|req\.file\b|req\.files\b|formData\(\))/;

const UPLOAD_LIMIT_SIGNAL_REGEX =
  /\b(?:fileSize|maxFileSize|maxSize|limits\s*:|fileFilter|mimetype|contentType|allowedTypes|ALLOWED_MIME)\b/i;

const LLM_CALL_REGEX =
  /\b(?:openai\.(?:chat\.completions|responses)\.create|anthropic\.messages\.create|generateText\s*\(|streamText\s*\(|generateContent\s*\(|ChatCompletion\.create)\b/;

const LLM_SAFEGUARD_REGEX =
  /\b(?:max_tokens|maxTokens|max_output_tokens|maxOutputTokens|max_completion_tokens|rateLimit|ratelimit|limiter|throttle)\b/i;

export async function runSafeguardsScan(ctx: StaticScanContext): Promise<ModuleResult> {
  return runStaticModule('STAT-006', 'Upload & LLM Spend Safeguards', () => {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      if (!isCodeFile(file.relPath)) continue;

      // 1. File upload handlers without MIME type or file size limits
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        if (!UPLOAD_SIGNAL_REGEX.test(line)) continue;

        const lineNum = i + 1;
        const windowText = file.lines.slice(Math.max(0, i - 5), i + 25).join('\n');
        if (!UPLOAD_LIMIT_SIGNAL_REGEX.test(windowText)) {
          findings.push({
            id: 'STAT-006',
            title: 'File upload handler missing size or MIME type restrictions',
            severity: 'MEDIUM',
            category: 'Production Safety',
            location: `${file.relPath}:${lineNum}`,
            evidence: line.trim().slice(0, 180),
            reproduction: `Inspect ${file.relPath}:${lineNum} for upload size caps and MIME/content-type allowlists.`,
            whyItMatters:
              'Unrestricted file uploads let attackers exhaust disk/memory with gigabyte payloads (DoS) or upload executable scripts/HTML files that lead to stored XSS or server compromise.',
            howToFix:
              'Enforce a strict maximum file size limit (e.g., 5 MB) and validate allowed MIME types/extensions before storing uploaded files.\n\n' +
              `AI Fix Prompt: "Add file size limits (e.g., 5MB) and an explicit MIME type allowlist to the file upload handler at ${file.relPath}:${lineNum}."`,
          });
          break;
        }
      }

      // 2. LLM SDK call sites lacking max_tokens / rate-limit safeguards
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        if (!LLM_CALL_REGEX.test(line)) continue;

        const lineNum = i + 1;
        const windowText = file.lines.slice(Math.max(0, i - 10), i + 20).join('\n');
        if (!LLM_SAFEGUARD_REGEX.test(windowText) && !LLM_SAFEGUARD_REGEX.test(file.content)) {
          findings.push({
            id: 'STAT-006',
            title: 'LLM API call missing token cap or rate-limiting safeguard',
            severity: 'MEDIUM',
            category: 'Production Safety',
            location: `${file.relPath}:${lineNum}`,
            evidence: line.trim().slice(0, 180),
            reproduction: `Inspect ${file.relPath}:${lineNum} for max_tokens / maxOutputTokens and rate-limiting middleware.`,
            whyItMatters:
              'Calling paid LLM APIs without a `max_tokens` cap or per-user rate limit allows a single abusive user or automated script to run up thousands of dollars in API bills overnight.',
            howToFix:
              'Set an explicit `max_tokens` (or `maxOutputTokens`) cap on every LLM request and wrap AI endpoints with per-user rate limiting and spend quotas.\n\n' +
              `AI Fix Prompt: "Add an explicit max_tokens cap and per-user rate limiting to the LLM call at ${file.relPath}:${lineNum}."`,
          });
        }
      }
    }

    return findings;
  });
}
