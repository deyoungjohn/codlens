import fs from 'node:fs/promises';
import path from 'node:path';
import type {
  AiSdk,
  DatabaseBaaS,
  DetectedStack,
  Framework,
  Language,
  PackageManager,
  PaymentProvider,
} from '../types.js';

export const DEFAULT_IGNORE_DIRS = new Set([
  'node_modules',
  '.git',
  '.next',
  'dist',
  'venv',
  '.venv',
  '__pycache__',
  'build',
  'coverage',
]);

export interface DetectOptions {
  ignorePaths?: string[];
  maxFiles?: number;
}

interface PackageJsonShape {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

function toPosixRelative(rootDir: string, fullPath: string): string {
  const rel = path.relative(rootDir, fullPath);
  return rel.split(path.sep).join(path.posix.sep);
}

async function pathExists(targetPath: string): Promise<boolean> {
  try {
    await fs.access(targetPath);
    return true;
  } catch {
    return false;
  }
}

async function readTextSafe(filePath: string): Promise<string | null> {
  try {
    return await fs.readFile(filePath, 'utf8');
  } catch {
    return null;
  }
}

async function collectFiles(
  rootDir: string,
  ignoreSet: Set<string>,
  maxFiles: number,
): Promise<string[]> {
  const files: string[] = [];

  async function walk(currentDir: string): Promise<void> {
    if (files.length >= maxFiles) return;

    let entries;
    try {
      entries = await fs.readdir(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (files.length >= maxFiles) break;

      const fullPath = path.join(currentDir, entry.name);
      const relPosix = toPosixRelative(rootDir, fullPath);

      if (ignoreSet.has(entry.name) || ignoreSet.has(relPosix)) {
        continue;
      }

      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile()) {
        files.push(relPosix);
      }
    }
  }

  await walk(rootDir);
  return files;
}

function isNextApiRoute(relPath: string): boolean {
  return (
    /(?:^|\/)(?:src\/)?app\/api\/.+\/route\.[jt]sx?$/.test(relPath) ||
    /(?:^|\/)(?:src\/)?pages\/api\/.+\.[jt]sx?$/.test(relPath)
  );
}

function isLikelyRouteFile(relPath: string, content: string): boolean {
  if (isNextApiRoute(relPath)) {
    return true;
  }

  if (/\.[jt]sx?$/.test(relPath)) {
    if (
      /\b(?:app|router|server|fastify)\.(?:get|post|put|patch|delete|all|use)\s*\(/i.test(content) ||
      /export\s+async\s+function\s+(?:GET|POST|PUT|PATCH|DELETE)\b/.test(content)
    ) {
      return true;
    }
  }

  if (/\.py$/.test(relPath)) {
    if (
      /@(?:app|router|bp|blueprint)\.(?:get|post|put|patch|delete|route|api_route)\s*\(/i.test(
        content,
      ) ||
      /\burlpatterns\s*=/.test(content)
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Auto-detects the frameworks, databases/BaaS, payment providers, AI SDKs,
 * languages, and candidate API route files for a target repository.
 * Strictly read-only.
 */
export async function detectStack(
  targetDir: string,
  options: DetectOptions = {},
): Promise<DetectedStack> {
  const resolvedTarget = path.resolve(targetDir);
  const stat = await fs.stat(resolvedTarget).catch(() => null);
  if (!stat || !stat.isDirectory()) {
    throw new Error(`Target directory does not exist or is not a directory: ${resolvedTarget}`);
  }

  const ignoreSet = new Set<string>(DEFAULT_IGNORE_DIRS);
  for (const p of options.ignorePaths ?? []) {
    ignoreSet.add(p.replace(/\/+$/, ''));
  }

  const frameworks = new Set<Framework>();
  const databases = new Set<DatabaseBaaS>();
  const paymentProviders = new Set<PaymentProvider>();
  const aiSdks = new Set<AiSdk>();
  const languages = new Set<Language>();
  const packageManagers = new Set<PackageManager>();
  const routeFiles = new Set<string>();

  const hasGit = await pathExists(path.join(resolvedTarget, '.git'));
  const files = await collectFiles(resolvedTarget, ignoreSet, options.maxFiles ?? 2500);

  // Check lockfiles for package managers
  if (files.includes('package-lock.json')) packageManagers.add('npm');
  if (files.includes('pnpm-lock.yaml')) packageManagers.add('pnpm');
  if (files.includes('yarn.lock')) packageManagers.add('yarn');
  if (files.includes('poetry.lock')) packageManagers.add('poetry');
  if (files.includes('uv.lock')) packageManagers.add('uv');
  if (files.includes('requirements.txt')) packageManagers.add('pip');

  // Inspect package.json dependencies
  const pkgRaw = await readTextSafe(path.join(resolvedTarget, 'package.json'));
  if (pkgRaw) {
    try {
      const pkg = JSON.parse(pkgRaw) as PackageJsonShape;
      const deps = new Set<string>([
        ...Object.keys(pkg.dependencies ?? {}),
        ...Object.keys(pkg.devDependencies ?? {}),
      ]);

      if (deps.has('next')) frameworks.add('nextjs');
      if (deps.has('express')) frameworks.add('express');
      if (deps.has('fastify')) frameworks.add('fastify');
      if (deps.has('hono')) frameworks.add('hono');
      if (deps.has('vite') && deps.has('react')) frameworks.add('react-vite');

      if (deps.has('prisma') || deps.has('@prisma/client')) databases.add('prisma');
      if (deps.has('drizzle-orm')) databases.add('drizzle');
      if (deps.has('@supabase/supabase-js') || deps.has('@supabase/ssr')) databases.add('supabase');
      if (deps.has('firebase') || deps.has('firebase-admin')) databases.add('firebase');
      if (deps.has('mongodb') || deps.has('mongoose')) databases.add('mongodb');

      if (deps.has('stripe')) paymentProviders.add('stripe');
      if (deps.has('paystack') || deps.has('paystack-api') || deps.has('@paystack/inline-js')) {
        paymentProviders.add('paystack');
      }
      if (deps.has('flutterwave-node-v3') || deps.has('flutterwave-react-v3')) {
        paymentProviders.add('flutterwave');
      }

      if (deps.has('openai')) aiSdks.add('openai');
      if (deps.has('@anthropic-ai/sdk')) aiSdks.add('anthropic');
      if (deps.has('@google/genai') || deps.has('@google/generative-ai')) {
        aiSdks.add('google-genai');
      }
      if (deps.has('ai') || deps.has('@ai-sdk/openai') || deps.has('@ai-sdk/anthropic')) {
        aiSdks.add('vercel-ai');
      }

      if (deps.has('typescript')) languages.add('typescript');
      if (packageManagers.size === 0) packageManagers.add('npm');
    } catch {
      // Malformed package.json — continue with file-based heuristics
    }
  }

  // Inspect Python dependency manifests
  const pyManifestTexts: string[] = [];
  for (const manifest of ['requirements.txt', 'pyproject.toml', 'Pipfile']) {
    const content = await readTextSafe(path.join(resolvedTarget, manifest));
    if (content) {
      pyManifestTexts.push(content.toLowerCase());
      languages.add('python');
    }
  }
  const pyDeps = pyManifestTexts.join('\n');
  if (pyDeps) {
    if (/\bfastapi\b/.test(pyDeps)) frameworks.add('fastapi');
    if (/\bdjango\b/.test(pyDeps)) frameworks.add('django');
    if (/\bflask\b/.test(pyDeps)) frameworks.add('flask');
    if (/\bsupabase\b/.test(pyDeps)) databases.add('supabase');
    if (/\bfirebase-admin\b/.test(pyDeps)) databases.add('firebase');
    if (/\bpymongo\b|\bmotor\b/.test(pyDeps)) databases.add('mongodb');
    if (/\bstripe\b/.test(pyDeps)) paymentProviders.add('stripe');
    if (/\bpaystack\b/.test(pyDeps)) paymentProviders.add('paystack');
    if (/\bopenai\b/.test(pyDeps)) aiSdks.add('openai');
    if (/\banthropic\b/.test(pyDeps)) aiSdks.add('anthropic');
    if (/\bgoogle-genai\b|\bgoogle-generativeai\b/.test(pyDeps)) aiSdks.add('google-genai');
  }

  // Structural file-based signals
  if (await pathExists(path.join(resolvedTarget, 'supabase'))) {
    databases.add('supabase');
  }

  for (const relPath of files) {
    const lower = relPath.toLowerCase();

    if (/\.tsx?$/.test(lower)) languages.add('typescript');
    else if (/\.[cm]?jsx?$/.test(lower)) languages.add('javascript');
    else if (/\.py$/.test(lower)) languages.add('python');

    if (lower.endsWith('schema.prisma')) databases.add('prisma');
    if (/(?:^|\/)drizzle\.config\.[jt]s$/.test(lower)) databases.add('drizzle');
    if (lower.endsWith('firestore.rules')) databases.add('firebase');
    if (lower.startsWith('supabase/')) databases.add('supabase');
    if (isNextApiRoute(relPath)) {
      frameworks.add('nextjs');
      routeFiles.add(relPath);
    }
  }

  // Lightweight content inspection on source files for route discovery and payment/AI hints
  const sourceFiles = files.filter((f) => /\.(?:[jt]sx?|[cm]?js|py)$/.test(f));
  const maxContentScan = Math.min(sourceFiles.length, 300);

  for (let i = 0; i < maxContentScan; i++) {
    const relPath = sourceFiles[i];
    const content = await readTextSafe(path.join(resolvedTarget, relPath));
    if (!content) continue;

    if (isLikelyRouteFile(relPath, content)) {
      routeFiles.add(relPath);
    }

    if (/x-paystack-signature|api\.paystack\.co/i.test(content)) {
      paymentProviders.add('paystack');
    }
    if (/stripe-signature|stripe\.webhooks\.constructEvent/i.test(content)) {
      paymentProviders.add('stripe');
    }
    if (/verif-hash|api\.flutterwave\.com/i.test(content)) {
      paymentProviders.add('flutterwave');
    }
  }

  return {
    frameworks: [...frameworks].sort(),
    databases: [...databases].sort(),
    paymentProviders: [...paymentProviders].sort(),
    aiSdks: [...aiSdks].sort(),
    languages: [...languages].sort(),
    packageManagers: [...packageManagers].sort(),
    hasGit,
    routeFiles: [...routeFiles].sort(),
  };
}
