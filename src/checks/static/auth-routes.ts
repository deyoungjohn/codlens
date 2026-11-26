import type { Finding, ModuleResult } from '../../types.js';
import { isCodeFile, isTestOrMockFile, runStaticModule, type StaticScanContext } from './utils.js';

const AUTH_SIGNAL_REGEX =
  /\b(?:requireAuth|authenticate|authMiddleware|isAuthenticated|verifyToken|verifyJwt|jwt\.verify|getServerSession|getSession|auth\(\)|currentUser|req\.user|request\.user|getAuth|supabase\.auth\.getUser|Depends\s*\(\s*get_current_user|login_required|permission_classes|preHandler\s*:|(?:verify|require|check|assert|ensure|validate)[A-Za-z0-9_]*(?:Auth|Session|Token|Operator|Admin|User|Signature|ApiKey))\b/i;

const FILE_LEVEL_AUTH_USE_REGEX =
  /\b(?:app|router)\.use\s*\([^)]*(?:auth|authenticate|verifyToken|requireAuth|session)/i;

function isAllowlistedPath(routePath: string, allowlist: string[]): boolean {
  const normalized = routePath.toLowerCase();
  // Always allow health, login, register, signup, webhook endpoints by convention
  if (
    /\/(?:health|healthz|ping|login|signin|register|signup|logout|webhooks?)(?:\/|$)/i.test(
      normalized,
    )
  ) {
    return true;
  }
  return allowlist.some((allowed) => normalized.includes(allowed.toLowerCase()));
}

function deriveNextRoutePath(relPath: string): string | null {
  const appMatch = /(?:^|\/)(?:src\/)?app(\/api\/.+)\/route\.[jt]sx?$/.exec(relPath);
  if (appMatch) return appMatch[1];
  const pagesMatch = /(?:^|\/)(?:src\/)?pages(\/api\/.+)\.[jt]sx?$/.exec(relPath);
  if (pagesMatch) return pagesMatch[1];
  return null;
}

function hasAuthSignal(text: string, customHelpers: string[]): boolean {
  if (AUTH_SIGNAL_REGEX.test(text)) return true;
  return customHelpers.some((helper) => helper.length > 0 && text.includes(helper));
}

export async function runAuthRoutesScan(ctx: StaticScanContext): Promise<ModuleResult> {
  return runStaticModule('STAT-003', 'Missing Route Auth Heuristics', () => {
    const findings: Finding[] = [];
    const allowlist = ctx.config.static.publicEndpointsAllowlist;
    const customHelpers = ctx.config.static.customAuthHelpers ?? [];

    for (const file of ctx.files) {
      if (!isCodeFile(file.relPath)) continue;
      if (!ctx.includeTests && isTestOrMockFile(file.relPath)) continue;

      const hasFileLevelAuthMiddleware = FILE_LEVEL_AUTH_USE_REGEX.test(file.content);

      // 1. Next.js App Router (`app/api/**/route.ts`)
      const nextRoutePath = deriveNextRoutePath(file.relPath);
      if (nextRoutePath && !isAllowlistedPath(nextRoutePath, allowlist)) {
        const handlerRegex = /export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b/g;
        let match: RegExpExecArray | null;
        while ((match = handlerRegex.exec(file.content)) !== null) {
          const method = match[1];
          const isAdminRoute = /\/admin(?:\/|$)/i.test(nextRoutePath);
          if (method === 'GET' && !isAdminRoute) continue;

          const lineNum = file.content.slice(0, match.index).split(/\r?\n/).length;
          const windowText = file.lines.slice(lineNum - 1, lineNum + 35).join('\n');

          if (!hasAuthSignal(windowText, customHelpers)) {
            findings.push({
              id: 'STAT-003',
              title: `Potentially unprotected Next.js route: ${method} ${nextRoutePath}`,
              severity: 'HIGH',
              category: 'Auth & Access Control',
              location: `${file.relPath}:${lineNum}`,
              evidence: file.lines[lineNum - 1]?.trim().slice(0, 180) ?? `${method} ${nextRoutePath}`,
              reproduction: `Inspect ${file.relPath}:${lineNum} or test unauthenticated ${method} ${nextRoutePath}.`,
              whyItMatters:
                'API routes that mutate data or expose admin data without verifying a server-side session allow any unauthenticated attacker on the internet to invoke them directly.',
              howToFix:
                `Add a server-side session/auth verification check at the top of the ${method} handler in ${file.relPath} and return 401 Unauthorized when missing.\n\n` +
                `AI Fix Prompt: "Add server-side authentication verification at the start of the ${method} handler in ${file.relPath}:${lineNum}, returning 401 Unauthorized if no valid session or token is present."`,
            });
          }
        }
        continue;
      }

      // 2. Express / Fastify / Hono routes: app.post('/api/...', ...)
      const expressRegex =
        /\b(?:app|router|fastify)\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
      const expressMatches: Array<{ method: string; routePath: string; index: number; lineNum: number }> = [];
      let exMatch: RegExpExecArray | null;
      while ((exMatch = expressRegex.exec(file.content)) !== null) {
        expressMatches.push({
          method: exMatch[1].toUpperCase(),
          routePath: exMatch[2],
          index: exMatch.index,
          lineNum: file.content.slice(0, exMatch.index).split(/\r?\n/).length,
        });
      }

      for (let idx = 0; idx < expressMatches.length; idx++) {
        const { method, routePath, index, lineNum } = expressMatches[idx];
        const isAdminRoute = /\/admin(?:\/|$)/i.test(routePath);

        if (isAllowlistedPath(routePath, allowlist)) continue;
        if (method === 'GET' && !isAdminRoute) continue;

        const nextLineNum =
          idx + 1 < expressMatches.length ? expressMatches[idx + 1].lineNum : file.lines.length + 1;
        const endIdx = Math.min(lineNum + 20, nextLineNum - 1);
        const snippetWindow = file.lines.slice(lineNum - 1, Math.max(lineNum, endIdx)).join('\n');

        // Check if auth middleware is mounted globally before this line or inside the route
        const precedingContent = file.content.slice(0, index);
        const hasPriorAuthUse =
          hasFileLevelAuthMiddleware && FILE_LEVEL_AUTH_USE_REGEX.test(precedingContent);

        if (!hasPriorAuthUse && !hasAuthSignal(snippetWindow, customHelpers)) {
          findings.push({
            id: 'STAT-003',
            title: `Potentially unprotected route: ${method} ${routePath}`,
            severity: 'HIGH',
            category: 'Auth & Access Control',
            location: `${file.relPath}:${lineNum}`,
            evidence: file.lines[lineNum - 1]?.trim().slice(0, 180) ?? `${method} ${routePath}`,
            reproduction: `Inspect ${file.relPath}:${lineNum} or send an unauthenticated ${method} request to ${routePath}.`,
            whyItMatters:
              'Mutating or administrative endpoints without server-side authentication middleware can be called by anyone, bypassing frontend UI guards completely.',
            howToFix:
              `Attach an authentication middleware (and role check for admin routes) to \`${method} ${routePath}\` in ${file.relPath}.\n\n` +
              `AI Fix Prompt: "Protect the ${method} ${routePath} route at ${file.relPath}:${lineNum} with server-side authentication middleware that returns 401 for unauthenticated requests."`,
          });
        }
      }

      // 3. Python FastAPI / Flask routes: @app.post("/api/...")
      if (file.relPath.endsWith('.py')) {
        const pyRouteRegex =
          /@(?:app|router|bp|blueprint)\.(get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]/gi;
        const pyMatches: Array<{ method: string; routePath: string; lineNum: number }> = [];
        let pyMatch: RegExpExecArray | null;
        while ((pyMatch = pyRouteRegex.exec(file.content)) !== null) {
          pyMatches.push({
            method: pyMatch[1].toUpperCase(),
            routePath: pyMatch[2],
            lineNum: file.content.slice(0, pyMatch.index).split(/\r?\n/).length,
          });
        }

        for (let idx = 0; idx < pyMatches.length; idx++) {
          const { method, routePath, lineNum } = pyMatches[idx];
          const isAdminRoute = /\/admin(?:\/|$)/i.test(routePath);

          if (isAllowlistedPath(routePath, allowlist)) continue;
          if (method === 'GET' && !isAdminRoute) continue;

          const nextLineNum =
            idx + 1 < pyMatches.length ? pyMatches[idx + 1].lineNum : file.lines.length + 1;
          const endIdx = Math.min(lineNum + 20, nextLineNum - 1);
          const snippetWindow = file.lines.slice(lineNum - 1, Math.max(lineNum, endIdx)).join('\n');

          if (!hasAuthSignal(snippetWindow, customHelpers)) {
            findings.push({
              id: 'STAT-003',
              title: `Potentially unprotected Python route: ${method} ${routePath}`,
              severity: 'HIGH',
              category: 'Auth & Access Control',
              location: `${file.relPath}:${lineNum}`,
              evidence: file.lines[lineNum - 1]?.trim().slice(0, 180) ?? `${method} ${routePath}`,
              reproduction: `Inspect ${file.relPath}:${lineNum} or send an unauthenticated ${method} request to ${routePath}.`,
              whyItMatters:
                'Endpoints that modify state or expose privileged data without server-side authentication can be abused directly via HTTP requests.',
              howToFix:
                `Add an authentication dependency (e.g., \`Depends(get_current_user)\` or \`@login_required\`) to \`${method} ${routePath}\` in ${file.relPath}.\n\n` +
                `AI Fix Prompt: "Add server-side authentication enforcement to ${method} ${routePath} at ${file.relPath}:${lineNum} so unauthenticated requests receive HTTP 401."`,
            });
          }
        }
      }
    }

    return findings;
  });
}
