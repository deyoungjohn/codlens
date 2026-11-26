import type { Finding, ModuleResult } from '../../types.js';
import type { DynamicContext } from './http-client.js';

export class PlaywrightUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PlaywrightUnavailableError';
  }
}

/**
 * Optional browser inspection probe using Playwright, strictly lazy-loaded via dynamic import().
 * Never imported unless `--browser` is explicitly passed.
 */
export async function runBrowserProbe(ctx: DynamicContext): Promise<ModuleResult> {
  const start = Date.now();
  const playwrightPkg = 'playwright';

  let playwright: {
    chromium?: {
      launch: (opts?: Record<string, unknown>) => Promise<{
        newPage: () => Promise<{
          on: (event: string, cb: (arg: unknown) => void) => void;
          goto: (url: string, opts?: Record<string, unknown>) => Promise<unknown>;
          close: () => Promise<void>;
        }>;
        close: () => Promise<void>;
      }>;
    };
  };

  try {
    playwright = (await import(playwrightPkg)) as typeof playwright;
  } catch {
    throw new PlaywrightUnavailableError(
      'Playwright is not installed. To use --browser mode in WSL2/Linux, run:\n' +
        '  npm install -D playwright && npx playwright install --with-deps chromium',
    );
  }

  if (!playwright.chromium) {
    throw new PlaywrightUnavailableError(
      'Playwright Chromium module is unavailable. Run: npx playwright install --with-deps chromium',
    );
  }

  let browser;
  try {
    browser = await playwright.chromium.launch({ headless: true });
  } catch {
    throw new PlaywrightUnavailableError(
      'Playwright Chromium browser binary is not installed. Run:\n' +
        '  npx playwright install --with-deps chromium',
    );
  }

  const findings: Finding[] = [];
  try {
    const page = await browser.newPage();
    const consoleErrors: string[] = [];
    page.on('pageerror', (err: unknown) => {
      consoleErrors.push(err instanceof Error ? err.message : String(err));
    });

    await page.goto(ctx.baseUrl, { waitUntil: 'domcontentloaded', timeout: ctx.timeoutMs });

    if (consoleErrors.length > 0) {
      findings.push({
        id: 'DYN-BROWSER',
        title: `Uncaught client-side runtime errors detected (${consoleErrors.length})`,
        severity: 'MEDIUM',
        category: 'Production Safety',
        location: `GET ${ctx.baseUrl}`,
        evidence: consoleErrors.slice(0, 3).join(' | ').slice(0, 220),
        reproduction: `Open ${ctx.baseUrl} in a browser and check DevTools Console for uncaught page errors.`,
        whyItMatters:
          'Uncaught runtime exceptions on initial page load can break user flows and expose internal client state or stack traces.',
        howToFix:
          'Add React Error Boundaries / global error handlers and resolve the uncaught exception reported in browser DevTools.\n\n' +
          'AI Fix Prompt: "Fix the uncaught browser runtime error on initial page load and wrap root UI components in an Error Boundary."',
      });
    }

    await page.close();
  } finally {
    await browser.close();
  }

  return {
    moduleId: 'DYN-BROWSER',
    moduleName: 'Browser Runtime Inspection (Playwright)',
    kind: 'dynamic',
    status: 'passed',
    durationMs: Date.now() - start,
    findings,
  };
}
