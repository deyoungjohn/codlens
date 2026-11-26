import fs from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';
import type { CodlensConfig, DetectedStack } from '../types.js';

const HttpMethodSchema = z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']);

/**
 * Ensures `tokenEnvVar` is an environment variable name (e.g. CODLENS_USER_A_TOKEN)
 * rather than a hardcoded secret, JWT, or Bearer token.
 */
const EnvVarNameSchema = z
  .string()
  .min(1, 'tokenEnvVar must be a non-empty environment variable name')
  .refine(
    (val) => !/^(?:bearer\s+|eyJ|sk_live_|sk_test_|sk-ant-|ghp_|AIza)/i.test(val.trim()),
    {
      message:
        'tokenEnvVar appears to contain a raw token or secret. Store only the environment variable name (e.g., "CODLENS_USER_A_TOKEN") in codlens.config.json.',
    },
  )
  .refine((val) => /^[A-Z_][A-Z0-9_]*$/.test(val.trim()), {
    message:
      'tokenEnvVar must be a valid uppercase environment variable identifier (e.g., "CODLENS_USER_A_TOKEN").',
  });

const EndpointConfigSchema = z.object({
  method: HttpMethodSchema,
  path: z.string().startsWith('/', 'Endpoint path must start with "/"'),
});

const IdorTargetSchema = z.object({
  method: HttpMethodSchema,
  pathTemplate: z.string().startsWith('/', 'pathTemplate must start with "/"'),
  ownerBResourceId: z.string().min(1, 'ownerBResourceId must not be empty'),
});

const FuzzEndpointSchema = z.object({
  method: HttpMethodSchema,
  path: z.string().startsWith('/', 'Endpoint path must start with "/"'),
  sampleValidBody: z.record(z.unknown()).default({}),
});

const WebhookEndpointSchema = z.object({
  provider: z.enum(['paystack', 'stripe', 'flutterwave']),
  path: z.string().startsWith('/', 'Webhook path must start with "/"'),
});

const RateLimitEndpointSchema = z.object({
  method: HttpMethodSchema,
  path: z.string().startsWith('/', 'Endpoint path must start with "/"'),
  burstCount: z.number().int().min(5).max(200).default(25),
});

const AuthUserSchema = z.object({
  tokenEnvVar: EnvVarNameSchema,
  resourceId: z.string().optional(),
});

const DynamicAuthSchema = z.object({
  strategy: z.enum(['bearer', 'cookie', 'header']).default('bearer'),
  headerName: z.string().optional(),
  cookieName: z.string().optional(),
  userA: AuthUserSchema.optional(),
  userB: AuthUserSchema.optional(),
});

const StaticConfigSchema = z
  .object({
    ignorePaths: z
      .array(z.string())
      .default(['node_modules', '.next', 'dist', 'coverage', 'venv', '__pycache__']),
    publicEndpointsAllowlist: z
      .array(z.string())
      .default(['/api/health', '/api/auth/login', '/api/auth/register']),
  })
  .default({});

const DynamicConfigSchema = z
  .object({
    enabled: z.boolean().default(true),
    auth: DynamicAuthSchema.optional(),
    protectedEndpoints: z.array(EndpointConfigSchema).default([]),
    idorTargets: z.array(IdorTargetSchema).default([]),
    profileUpdateEndpoint: EndpointConfigSchema.optional(),
    fuzzEndpoints: z.array(FuzzEndpointSchema).default([]),
    webhookEndpoints: z.array(WebhookEndpointSchema).default([]),
    rateLimitEndpoints: z.array(RateLimitEndpointSchema).default([]),
  })
  .default({});

export const CodlensConfigSchema = z.object({
  projectName: z.string().min(1, 'projectName is required'),
  targetDir: z.string().min(1, 'targetDir is required'),
  baseUrl: z.string().url('baseUrl must be a valid URL').optional(),
  static: StaticConfigSchema,
  dynamic: DynamicConfigSchema,
});

export class ConfigLoadError extends Error {
  public readonly code = 'CONFIG_ERROR';

  constructor(message: string) {
    super(message);
    this.name = 'ConfigLoadError';
  }
}

/**
 * Validates raw config data with Zod and returns a normalized CodlensConfig.
 */
export function parseConfig(raw: unknown, baseDir?: string): CodlensConfig {
  const result = CodlensConfigSchema.safeParse(raw);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.') || '<root>'}: ${i.message}`)
      .join('\n');
    throw new ConfigLoadError(`Invalid codlens.config.json:\n${issues}`);
  }

  const parsed = result.data;
  const resolvedTargetDir = baseDir
    ? path.resolve(baseDir, parsed.targetDir)
    : path.resolve(parsed.targetDir);

  return {
    ...parsed,
    targetDir: resolvedTargetDir,
  };
}

/**
 * Loads and validates a `codlens.config.json` file from disk.
 */
export async function loadConfig(configPath: string): Promise<CodlensConfig> {
  const resolvedConfigPath = path.resolve(configPath);
  let rawText: string;
  try {
    rawText = await fs.readFile(resolvedConfigPath, 'utf8');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new ConfigLoadError(`Failed to read config file at ${resolvedConfigPath}: ${msg}`);
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(rawText);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new ConfigLoadError(`Config file ${resolvedConfigPath} contains invalid JSON: ${msg}`);
  }

  return parseConfig(parsedJson, path.dirname(resolvedConfigPath));
}

/**
 * Creates a sensible default CodlensConfig for `--static-only` runs or `codlens init`.
 */
export function createDefaultConfig(
  targetDir: string,
  options: {
    baseUrl?: string;
    detectedStack?: DetectedStack;
    staticOnly?: boolean;
  } = {},
): CodlensConfig {
  const resolvedTarget = path.resolve(targetDir);
  const projectName = path.basename(resolvedTarget) || 'target-project';

  const webhookEndpoints: CodlensConfig['dynamic']['webhookEndpoints'] = [];
  for (const provider of options.detectedStack?.paymentProviders ?? []) {
    webhookEndpoints.push({
      provider,
      path: `/api/webhooks/${provider}`,
    });
  }

  return parseConfig({
    projectName,
    targetDir: resolvedTarget,
    ...(options.baseUrl ? { baseUrl: options.baseUrl } : {}),
    static: {
      ignorePaths: ['node_modules', '.next', 'dist', 'coverage', 'venv', '__pycache__'],
      publicEndpointsAllowlist: ['/api/health', '/api/auth/login', '/api/auth/register'],
    },
    dynamic: {
      enabled: !options.staticOnly,
      auth: {
        strategy: 'bearer',
        userA: {
          tokenEnvVar: 'CODLENS_USER_A_TOKEN',
          resourceId: 'resource_a_1',
        },
        userB: {
          tokenEnvVar: 'CODLENS_USER_B_TOKEN',
          resourceId: 'resource_b_2',
        },
      },
      protectedEndpoints: [],
      idorTargets: [],
      fuzzEndpoints: [],
      webhookEndpoints,
      rateLimitEndpoints: [],
    },
  });
}
