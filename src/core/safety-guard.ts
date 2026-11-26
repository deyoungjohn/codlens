import type { HttpMethod, SafetyCheckResult, SafetyGuardOptions } from '../types.js';

const DEFAULT_LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1']);
const MUTATING_METHODS = new Set<string>(['POST', 'PUT', 'PATCH', 'DELETE']);

export class SafetyGuardError extends Error {
  public readonly code = 'SAFETY_GUARD_BLOCKED';

  constructor(message: string) {
    super(message);
    this.name = 'SafetyGuardError';
  }
}

/**
 * Normalizes a URL hostname by lowercasing and stripping IPv6 brackets
 * (e.g., "[::1]" -> "::1", "LOCALHOST" -> "localhost").
 */
export function normalizeHostname(hostname: string): string {
  const trimmed = hostname.trim().toLowerCase();
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

/**
 * Returns true if the hostname is a permitted loopback / local development address.
 */
export function isLocalHost(hostname: string): boolean {
  const normalized = normalizeHostname(hostname);
  return DEFAULT_LOCAL_HOSTS.has(normalized);
}

/**
 * Validates that a target URL is safe to run dynamic probes against.
 * Refuses non-local URLs unless `options.allowNonLocal` is true.
 */
export function validateTargetUrl(
  rawUrl: string,
  options: SafetyGuardOptions = {},
): SafetyCheckResult {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return {
      allowed: false,
      normalizedHost: '',
      isLocal: false,
      reason: `Invalid target URL "${rawUrl}". Expected an http:// or https:// URL (e.g., http://localhost:3000).`,
    };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      allowed: false,
      normalizedHost: normalizeHostname(parsed.hostname),
      isLocal: false,
      reason: `Unsupported URL protocol "${parsed.protocol}". Only http: and https: are permitted.`,
    };
  }

  const normalizedHost = normalizeHostname(parsed.hostname);
  const local = isLocalHost(normalizedHost);

  if (!local && !options.allowNonLocal) {
    return {
      allowed: false,
      normalizedHost,
      isLocal: false,
      reason:
        `Refusing to run dynamic tests against non-local host "${normalizedHost}". ` +
        `Allowed default hosts are localhost, 127.0.0.1, 0.0.0.0, and ::1. ` +
        `Pass --allow-non-local to override for an authorized staging environment.`,
    };
  }

  return {
    allowed: true,
    normalizedHost,
    isLocal: local,
  };
}

/**
 * Throws SafetyGuardError if the target URL violates the production safety lock.
 */
export function assertSafeTargetUrl(
  rawUrl: string,
  options: SafetyGuardOptions = {},
): SafetyCheckResult {
  const result = validateTargetUrl(rawUrl, options);
  if (!result.allowed) {
    throw new SafetyGuardError(result.reason ?? 'Target URL blocked by safety guard.');
  }
  return result;
}

/**
 * Checks whether an HTTP method is permitted against a target URL.
 * Even when `--allow-non-local` is set, mutating requests (POST, PUT, PATCH, DELETE)
 * are refused against non-local hosts unless `allowMutations` or `ALLOW_MUTATIONS=true` is set.
 */
export function validateRequestMethod(
  rawUrl: string,
  method: HttpMethod | string,
  options: SafetyGuardOptions = {},
): SafetyCheckResult {
  const urlCheck = validateTargetUrl(rawUrl, options);
  if (!urlCheck.allowed) {
    return urlCheck;
  }

  const upperMethod = method.toUpperCase();
  const isMutating = MUTATING_METHODS.has(upperMethod);
  const mutationsAllowed =
    options.allowMutations ?? process.env.ALLOW_MUTATIONS?.toLowerCase() === 'true';

  if (!urlCheck.isLocal && isMutating && !mutationsAllowed) {
    return {
      allowed: false,
      normalizedHost: urlCheck.normalizedHost,
      isLocal: false,
      reason:
        `Refusing mutating ${upperMethod} request against non-local host "${urlCheck.normalizedHost}". ` +
        `Set ALLOW_MUTATIONS=true to explicitly permit mutating requests on non-local targets.`,
    };
  }

  return urlCheck;
}

/**
 * Throws SafetyGuardError if the HTTP method is blocked by the production safety lock.
 */
export function assertSafeRequestMethod(
  rawUrl: string,
  method: HttpMethod | string,
  options: SafetyGuardOptions = {},
): SafetyCheckResult {
  const result = validateRequestMethod(rawUrl, method, options);
  if (!result.allowed) {
    throw new SafetyGuardError(result.reason ?? 'HTTP method blocked by safety guard.');
  }
  return result;
}
