import fs from 'node:fs/promises';
import path from 'node:path';
import { DEFAULT_IGNORE_DIRS } from '../../core/detector.js';
import type { CodlensConfig, DetectedStack, Finding, ModuleResult } from '../../types.js';

export interface ScannedFile {
  relPath: string;
  fullPath: string;
  content: string;
  lines: string[];
}

export interface StaticScanContext {
  targetDir: string;
  config: CodlensConfig;
  stack: DetectedStack;
  files: ScannedFile[];
  includeTests?: boolean;
}

const SCANNABLE_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.py',
  '.sql',
  '.rules',
  '.env',
  '.json',
  '.yaml',
  '.yml',
  '.toml',
]);

const MAX_FILE_BYTES = 512 * 1024; // 512 KB

function toPosixRelative(rootDir: string, fullPath: string): string {
  return path.relative(rootDir, fullPath).split(path.sep).join(path.posix.sep);
}

function isScannableFile(filename: string): boolean {
  const lower = filename.toLowerCase();
  if (lower === '.env' || lower.startsWith('.env.') || lower === '.gitignore') {
    return true;
  }
  if (lower === 'firestore.rules' || lower === 'storage.rules') {
    return true;
  }
  const ext = path.extname(lower);
  return SCANNABLE_EXTENSIONS.has(ext);
}

/**
 * Masks a secret value, keeping at most the first 4 characters visible.
 */
export function maskSecret(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length <= 4) {
    return '****';
  }
  const visible = trimmed.slice(0, 4);
  const maskedLen = Math.min(Math.max(trimmed.length - 4, 4), 16);
  return `${visible}${'*'.repeat(maskedLen)}`;
}

/**
 * Redacts all occurrences of a secret value inside a code line.
 */
export function redactLine(line: string, secret: string): string {
  if (!secret) return line.trim();
  const masked = maskSecret(secret);
  return line.split(secret).join(masked).trim().slice(0, 200);
}

/**
 * Computes Shannon entropy (bits per character) for a candidate secret string.
 */
export function shannonEntropy(str: string): number {
  if (!str) return 0;
  const counts = new Map<string, number>();
  for (const ch of str) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Read-only walk of the target directory collecting scannable text files.
 */
export async function collectStaticFiles(
  targetDir: string,
  ignorePaths: string[] = [],
  maxFiles = 2000,
): Promise<ScannedFile[]> {
  const resolvedRoot = path.resolve(targetDir);
  const ignoreSet = new Set<string>(DEFAULT_IGNORE_DIRS);
  for (const p of ignorePaths) {
    ignoreSet.add(p.replace(/\/+$/, ''));
  }

  const results: ScannedFile[] = [];

  async function walk(currentDir: string): Promise<void> {
    if (results.length >= maxFiles) return;

    let entries;
    try {
      entries = await fs.readdir(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (results.length >= maxFiles) break;

      const fullPath = path.join(currentDir, entry.name);
      const relPath = toPosixRelative(resolvedRoot, fullPath);

      if (ignoreSet.has(entry.name) || ignoreSet.has(relPath)) {
        continue;
      }

      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile() && isScannableFile(entry.name)) {
        try {
          const stat = await fs.stat(fullPath);
          if (stat.size > MAX_FILE_BYTES) continue;
          const content = await fs.readFile(fullPath, 'utf8');
          if (content.includes('\u0000')) continue; // skip binary
          results.push({
            relPath,
            fullPath,
            content,
            lines: content.split(/\r?\n/),
          });
        } catch {
          // ignore unreadable files
        }
      }
    }
  }

  await walk(resolvedRoot);
  return results;
}

/**
 * Helper to wrap a static check function into a standardized ModuleResult.
 */
export async function runStaticModule(
  moduleId: string,
  moduleName: string,
  fn: () => Promise<Finding[]> | Finding[],
): Promise<ModuleResult> {
  const start = Date.now();
  try {
    const findings = await fn();
    const hasHighOrCritical = findings.some(
      (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH',
    );
    return {
      moduleId,
      moduleName,
      kind: 'static',
      status: hasHighOrCritical ? 'failed' : 'passed',
      durationMs: Date.now() - start,
      findings,
    };
  } catch (err) {
    return {
      moduleId,
      moduleName,
      kind: 'static',
      status: 'error',
      durationMs: Date.now() - start,
      findings: [],
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export function isCodeFile(relPath: string): boolean {
  return /\.(?:[jt]sx?|[cm]?js|py)$/.test(relPath);
}

export function isCommentLine(line: string): boolean {
  const trimmed = line.trim();
  return (
    trimmed.startsWith('//') ||
    trimmed.startsWith('/*') ||
    trimmed.startsWith('*') ||
    trimmed.startsWith('#')
  );
}

export function isTestOrMockFile(relPath: string): boolean {
  return (
    /(?:^|\/)(?:__tests__|__mocks__|test|tests|e2e|mocks|fixtures)(?:\/|$)/i.test(relPath) ||
    /(?:\.|_)(?:test|spec|mock|fixture)\.[a-z0-9]+$/i.test(relPath)
  );
}

export function isDevScriptFile(relPath: string): boolean {
  return /(?:^|\/)scripts\/.+\.[cm]?[jt]sx?$/i.test(relPath);
}

export function isFrontendUiFile(relPath: string): boolean {
  return (
    /\.[jt]sx$/i.test(relPath) ||
    /(?:^|\/)(?:components|hooks|styles|ui)(?:\/|$)/i.test(relPath)
  );
}
