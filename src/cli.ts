#!/usr/bin/env node
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Command } from 'commander';
import { PlaywrightUnavailableError } from './checks/dynamic/browser-probe.js';
import { ConfigLoadError, createDefaultConfig, loadConfig } from './core/config-loader.js';
import { detectStack } from './core/detector.js';
import { formatReportTimestamp, runAudit } from './core/runner.js';
import { SafetyGuardError } from './core/safety-guard.js';
import { printConsoleSummary } from './reporters/console-reporter.js';
import { writeJsonReport } from './reporters/json-reporter.js';
import { writeMarkdownReport } from './reporters/markdown-reporter.js';
import { ExitCode, type CodlensConfig, type HttpMethod } from './types.js';

/**
 * Scans discovered route files in the target repo (read-only) to suggest starter endpoints
 * for `codlens init`.
 */
async function discoverStarterEndpoints(
  targetDir: string,
  routeFiles: string[],
  config: CodlensConfig,
): Promise<CodlensConfig> {
  const protectedSeen = new Set<string>();
  const webhookSeen = new Set<string>(config.dynamic.webhookEndpoints.map((w) => w.path));
  const rateLimitSeen = new Set<string>();

  for (const relPath of routeFiles.slice(0, 50)) {
    const fullPath = path.join(targetDir, relPath);
    let content: string;
    try {
      content = await fs.readFile(fullPath, 'utf8');
    } catch {
      continue;
    }

    const routeMatches: Array<{ method: HttpMethod; routePath: string }> = [];

    // Next.js App Router
    const nextApp = /(?:^|\/)(?:src\/)?app(\/api\/.+)\/route\.[jt]sx?$/.exec(relPath);
    if (nextApp) {
      const mRegex = /export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b/g;
      let m: RegExpExecArray | null;
      while ((m = mRegex.exec(content)) !== null) {
        routeMatches.push({ method: m[1] as HttpMethod, routePath: nextApp[1] });
      }
    }

    // Express / Fastify / Hono
    const exRegex =
      /\b(?:app|router|fastify)\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
    let ex: RegExpExecArray | null;
    while ((ex = exRegex.exec(content)) !== null) {
      routeMatches.push({ method: ex[1].toUpperCase() as HttpMethod, routePath: ex[2] });
    }

    // Python FastAPI / Flask
    if (relPath.endsWith('.py')) {
      const pyRegex =
        /@(?:app|router|bp|blueprint)\.(get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]/gi;
      let py: RegExpExecArray | null;
      while ((py = pyRegex.exec(content)) !== null) {
        routeMatches.push({ method: py[1].toUpperCase() as HttpMethod, routePath: py[2] });
      }
    }

    for (const { method, routePath } of routeMatches) {
      if (!routePath.startsWith('/')) continue;

      // Webhooks
      if (/webhook/i.test(routePath)) {
        if (!webhookSeen.has(routePath)) {
          const provider = /stripe/i.test(routePath)
            ? 'stripe'
            : /flutterwave/i.test(routePath)
              ? 'flutterwave'
              : 'paystack';
          config.dynamic.webhookEndpoints.push({ provider, path: routePath });
          webhookSeen.add(routePath);
        }
        continue;
      }

      // Auth / login / AI endpoints -> rate limit candidates
      if (/\/(?:login|signin|auth|ai|chat|generate)/i.test(routePath) && method === 'POST') {
        const key = `${method}:${routePath}`;
        if (!rateLimitSeen.has(key)) {
          config.dynamic.rateLimitEndpoints.push({ method, path: routePath, burstCount: 25 });
          rateLimitSeen.add(key);
        }
        continue;
      }

      // Skip health/register endpoints
      if (/\/(?:health|healthz|ping|register|signup)/i.test(routePath)) {
        continue;
      }

      // Profile update endpoint
      if (/\/profile(?:\/|$)/i.test(routePath) && (method === 'PATCH' || method === 'PUT')) {
        if (!config.dynamic.profileUpdateEndpoint) {
          config.dynamic.profileUpdateEndpoint = { method, path: routePath };
        }
      }

      // IDOR candidate (path with :id or [id])
      if (/:[a-zA-Z0-9_]+|\[[a-zA-Z0-9_]+\]/.test(routePath)) {
        const normalizedTemplate = routePath.replace(/\[([a-zA-Z0-9_]+)\]/g, ':$1');
        if (
          !config.dynamic.idorTargets.some(
            (t) => t.method === method && t.pathTemplate === normalizedTemplate,
          )
        ) {
          config.dynamic.idorTargets.push({
            method,
            pathTemplate: normalizedTemplate,
            ownerBResourceId: 'REPLACE_WITH_USER_B_RESOURCE_ID',
          });
        }
        continue;
      }

      // Protected endpoints
      const protKey = `${method}:${routePath}`;
      if (!protectedSeen.has(protKey)) {
        config.dynamic.protectedEndpoints.push({ method, path: routePath });
        protectedSeen.add(protKey);
      }

      // Fuzz candidate for POST/PUT/PATCH
      if (
        (method === 'POST' || method === 'PUT' || method === 'PATCH') &&
        !config.dynamic.fuzzEndpoints.some((f) => f.method === method && f.path === routePath)
      ) {
        config.dynamic.fuzzEndpoints.push({
          method,
          path: routePath,
          sampleValidBody: { quantity: 1 },
        });
      }
    }
  }

  return config;
}

const program = new Command();

program
  .name('codlens')
  .description('Standalone CLI audit test harness for AI-generated full-stack web applications')
  .version('0.1.0');

program
  .command('init')
  .description('Scan a target repository (read-only) and generate a starter codlens.config.json')
  .requiredOption('-t, --target <path>', 'Path to the target repository to inspect')
  .option('-o, --output <path>', 'Output path for generated config', './codlens.config.json')
  .option('-u, --base-url <url>', 'Local or staging base URL', 'http://localhost:3000')
  .action(async (opts: { target: string; output: string; baseUrl: string }) => {
    try {
      const targetDir = path.resolve(opts.target);
      const outputPath = path.resolve(opts.output);

      const stack = await detectStack(targetDir);
      const starter = createDefaultConfig(targetDir, {
        baseUrl: opts.baseUrl,
        detectedStack: stack,
      });

      const enriched = await discoverStarterEndpoints(targetDir, stack.routeFiles, starter);
      const relativeTarget = path.relative(path.dirname(outputPath), targetDir) || '.';
      const writableConfig = {
        ...enriched,
        targetDir: relativeTarget.split(path.sep).join(path.posix.sep),
      };

      await fs.mkdir(path.dirname(outputPath), { recursive: true });
      await fs.writeFile(outputPath, `${JSON.stringify(writableConfig, null, 2)}\n`, 'utf8');

      console.log(`[codlens] Generated starter config at ${outputPath}`);
      console.log(
        `[codlens] Detected stack: frameworks=[${stack.frameworks.join(', ') || 'none'}], ` +
          `databases=[${stack.databases.join(', ') || 'none'}], ` +
          `payments=[${stack.paymentProviders.join(', ') || 'none'}], ` +
          `routes=${stack.routeFiles.length}`,
      );
      process.exitCode = ExitCode.PASS;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[codlens] init error: ${msg}`);
      process.exitCode = ExitCode.HARNESS_ERROR;
    }
  });

program
  .command('run')
  .description('Run static and dynamic security audits against a target project')
  .option('-c, --config <path>', 'Path to codlens.config.json')
  .option('-t, --target <path>', 'Path to target project directory')
  .option('-u, --base-url <url>', 'Override target base URL for dynamic checks')
  .option('-o, --out-dir <dir>', 'Base output directory for audit reports', './reports')
  .option('--static-only', 'Run only static source-code checks', false)
  .option('--allow-non-local', 'Allow dynamic checks against non-local URLs', false)
  .option('--browser', 'Enable optional Playwright browser checks (lazy-loaded)', false)
  .option('--skip-deps', 'Skip npm audit / dependency check', false)
  .action(
    async (opts: {
      config?: string;
      target?: string;
      baseUrl?: string;
      outDir: string;
      staticOnly: boolean;
      allowNonLocal: boolean;
      browser: boolean;
      skipDeps: boolean;
    }) => {
      try {
        if (!opts.config && !opts.target) {
          console.error('[codlens] Provide either --config <path> or --target <path>.');
          process.exitCode = ExitCode.HARNESS_ERROR;
          return;
        }

        const config = opts.config
          ? await loadConfig(opts.config)
          : createDefaultConfig(opts.target!, {
              baseUrl: opts.baseUrl,
              staticOnly: opts.staticOnly,
            });

        const report = await runAudit(config, {
          staticOnly: opts.staticOnly,
          baseUrl: opts.baseUrl,
          safety: { allowNonLocal: opts.allowNonLocal },
          browser: opts.browser,
          skipDepsAudit: opts.skipDeps,
        });

        const safeProjectSlug = report.projectName.replace(/[^a-zA-Z0-9._-]+/g, '-');
        const reportDir = path.resolve(
          opts.outDir,
          `${safeProjectSlug}-${formatReportTimestamp()}`,
        );

        const [jsonPath, mdPath] = await Promise.all([
          writeJsonReport(reportDir, report),
          writeMarkdownReport(reportDir, report),
        ]);

        printConsoleSummary(report, { jsonPath, mdPath });
        process.exitCode = report.summary.exitCode;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (err instanceof SafetyGuardError) {
          console.error(`[codlens] Safety Guard Blocked: ${msg}`);
        } else if (err instanceof ConfigLoadError) {
          console.error(`[codlens] Configuration Error: ${msg}`);
        } else if (err instanceof PlaywrightUnavailableError) {
          console.error(`[codlens] Browser Mode Unavailable:\n${msg}`);
        } else {
          console.error(`[codlens] Harness Error: ${msg}`);
        }
        process.exitCode = ExitCode.HARNESS_ERROR;
      }
    },
  );

program
  .command('self-test')
  .description('Run the built-in Codlens self-verification Vitest suite')
  .action(async () => {
    const cliDir = path.dirname(fileURLToPath(import.meta.url));
    const repoRoot = path.resolve(cliDir, '..');
    const child = spawn('npm', ['test'], {
      cwd: repoRoot,
      stdio: 'inherit',
    });
    const code = await new Promise<number>((resolve) => {
      child.on('close', (c) => resolve(c ?? 2));
      child.on('error', () => resolve(2));
    });
    process.exitCode = code === 0 ? ExitCode.PASS : ExitCode.AUDIT_FAILED;
  });

program.parseAsync(process.argv);
