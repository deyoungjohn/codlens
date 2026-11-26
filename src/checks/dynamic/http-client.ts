import { assertSafeRequestMethod, SafetyGuardError } from '../../core/safety-guard.js';
import type {
  CodlensConfig,
  DynamicAuthConfig,
  Finding,
  HttpMethod,
  ModuleResult,
  SafetyGuardOptions,
} from '../../types.js';

export interface DynamicContext {
  baseUrl: string;
  config: CodlensConfig;
  safety: SafetyGuardOptions;
  timeoutMs: number;
  maxRetries: number;
}

export interface HttpResponse {
  status: number;
  headers: Headers;
  bodyText: string;
  bodyJson: unknown;
  url: string;
}

export interface HttpRequestOptions {
  method: HttpMethod;
  path: string;
  headers?: Record<string, string>;
  body?: unknown;
  rawBody?: string;
  timeoutMs?: number;
  retries?: number;
}

export function joinUrl(baseUrl: string, endpointPath: string): string {
  const cleanBase = baseUrl.replace(/\/+$/, '');
  const cleanPath = endpointPath.startsWith('/') ? endpointPath : `/${endpointPath}`;
  return `${cleanBase}${cleanPath}`;
}

/**
 * Resolves auth headers for userA or userB from environment variables.
 * Returns null if the auth config or env var is not configured.
 */
export function resolveUserAuth(
  auth: DynamicAuthConfig | undefined,
  which: 'userA' | 'userB',
): { headers: Record<string, string>; envVarName: string } | null {
  const userCfg = auth?.[which];
  if (!auth || !userCfg?.tokenEnvVar) return null;

  const token = process.env[userCfg.tokenEnvVar];
  if (!token) return null;

  if (auth.strategy === 'cookie') {
    const cookieName = auth.cookieName ?? 'session';
    return {
      headers: { Cookie: `${cookieName}=${token}` },
      envVarName: userCfg.tokenEnvVar,
    };
  }

  if (auth.strategy === 'header') {
    const headerName = auth.headerName ?? 'x-api-key';
    return {
      headers: { [headerName]: token },
      envVarName: userCfg.tokenEnvVar,
    };
  }

  return {
    headers: { Authorization: `Bearer ${token}` },
    envVarName: userCfg.tokenEnvVar,
  };
}

/**
 * Generates a reproducible curl command with auth tokens referenced via $ENV_VAR
 * rather than printing raw secrets.
 */
export function buildCurlCommand(opts: {
  method: HttpMethod;
  url: string;
  headers?: Record<string, string>;
  authEnvVar?: string;
  authStrategy?: 'bearer' | 'cookie' | 'header';
  body?: string;
}): string {
  const parts: string[] = [`curl -i -X ${opts.method}`];

  if (opts.authEnvVar) {
    if (opts.authStrategy === 'cookie') {
      parts.push(`-H "Cookie: session=$${opts.authEnvVar}"`);
    } else {
      parts.push(`-H "Authorization: Bearer $${opts.authEnvVar}"`);
    }
  }

  for (const [k, v] of Object.entries(opts.headers ?? {})) {
    const lower = k.toLowerCase();
    if (lower === 'authorization' || lower === 'cookie') continue;
    parts.push(`-H "${k}: ${v.replace(/"/g, '\\"')}"`);
  }

  if (opts.body !== undefined) {
    const preview = opts.body.length > 240 ? `${opts.body.slice(0, 240)}...` : opts.body;
    parts.push(`-d '${preview.replace(/'/g, "'\\''")}'`);
  }

  parts.push(`"${opts.url}"`);
  return parts.join(' ');
}

/**
 * Executes an HTTP request through the Production Safety Guard with timeout and retry support.
 */
export async function safeFetch(
  ctx: DynamicContext,
  req: HttpRequestOptions,
): Promise<HttpResponse> {
  const url = joinUrl(ctx.baseUrl, req.path);

  // Always enforce safety guard (localhost/loopback lock + non-local mutation lock)
  assertSafeRequestMethod(url, req.method, ctx.safety);

  const headers: Record<string, string> = { ...(req.headers ?? {}) };
  let payload: string | undefined;

  if (req.rawBody !== undefined) {
    payload = req.rawBody;
    if (!Object.keys(headers).some((k) => k.toLowerCase() === 'content-type')) {
      headers['Content-Type'] = 'application/json';
    }
  } else if (req.body !== undefined) {
    payload = JSON.stringify(req.body);
    if (!Object.keys(headers).some((k) => k.toLowerCase() === 'content-type')) {
      headers['Content-Type'] = 'application/json';
    }
  }

  const timeoutMs = req.timeoutMs ?? ctx.timeoutMs;
  const maxRetries = req.retries ?? ctx.maxRetries;

  let lastErr: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const response = await fetch(url, {
        method: req.method,
        headers,
        body: req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS' ? undefined : payload,
        redirect: 'manual',
        signal: AbortSignal.timeout(timeoutMs),
      });

      const bodyText = await response.text();
      let bodyJson: unknown = null;
      try {
        bodyJson = bodyText ? JSON.parse(bodyText) : null;
      } catch {
        bodyJson = null;
      }

      return {
        status: response.status,
        headers: response.headers,
        bodyText,
        bodyJson,
        url,
      };
    } catch (err) {
      if (err instanceof SafetyGuardError) throw err;
      lastErr = err;
      if (attempt < maxRetries) {
        await new Promise((r) => setTimeout(r, 150 * (attempt + 1)));
      }
    }
  }

  const msg = lastErr instanceof Error ? lastErr.message : String(lastErr);
  throw new Error(`HTTP request failed for ${req.method} ${url}: ${msg}`);
}

export function truncateEvidence(text: string, maxLen = 220): string {
  const clean = text.replace(/\s+/g, ' ').trim();
  if (clean.length <= maxLen) return clean;
  return `${clean.slice(0, maxLen)}...`;
}

export async function runDynamicModule(
  moduleId: string,
  moduleName: string,
  fn: () => Promise<{ findings: Finding[]; skippedReason?: string }>,
): Promise<ModuleResult> {
  const start = Date.now();
  try {
    const { findings, skippedReason } = await fn();
    if (skippedReason && findings.length === 0) {
      return {
        moduleId,
        moduleName,
        kind: 'dynamic',
        status: 'skipped',
        durationMs: Date.now() - start,
        findings: [],
        skippedReason,
      };
    }
    const hasHighOrCritical = findings.some(
      (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH',
    );
    return {
      moduleId,
      moduleName,
      kind: 'dynamic',
      status: hasHighOrCritical ? 'failed' : 'passed',
      durationMs: Date.now() - start,
      findings,
    };
  } catch (err) {
    return {
      moduleId,
      moduleName,
      kind: 'dynamic',
      status: 'error',
      durationMs: Date.now() - start,
      findings: [],
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
