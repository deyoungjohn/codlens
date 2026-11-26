export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type Category =
  | 'Secrets'
  | 'Auth & Access Control'
  | 'Injection'
  | 'Validation & Payments'
  | 'Production Safety';

export type ReadinessVerdict =
  | 'BLOCKED FOR LAUNCH'
  | 'NEEDS HARDENING'
  | 'LAUNCH READY WITH NOTES';

export const ExitCode = {
  PASS: 0,
  AUDIT_FAILED: 1,
  HARNESS_ERROR: 2,
} as const;

export type ExitCodeValue = (typeof ExitCode)[keyof typeof ExitCode];

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'HEAD';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: Category;
  location: string;
  evidence: string;
  reproduction: string;
  whyItMatters: string;
  howToFix: string;
}

export interface ModuleResult {
  moduleId: string;
  moduleName: string;
  kind: 'static' | 'dynamic';
  status: 'passed' | 'failed' | 'skipped' | 'error';
  durationMs: number;
  findings: Finding[];
  error?: string;
  skippedReason?: string;
}

export type Framework =
  | 'nextjs'
  | 'express'
  | 'fastify'
  | 'hono'
  | 'react-vite'
  | 'fastapi'
  | 'django'
  | 'flask';

export type DatabaseBaaS =
  | 'prisma'
  | 'drizzle'
  | 'supabase'
  | 'firebase'
  | 'mongodb';

export type PaymentProvider = 'paystack' | 'stripe' | 'flutterwave';

export type AiSdk = 'openai' | 'anthropic' | 'google-genai' | 'vercel-ai';

export type Language = 'typescript' | 'javascript' | 'python';

export type PackageManager = 'npm' | 'pnpm' | 'yarn' | 'pip' | 'poetry' | 'uv';

export interface DetectedStack {
  frameworks: Framework[];
  databases: DatabaseBaaS[];
  paymentProviders: PaymentProvider[];
  aiSdks: AiSdk[];
  languages: Language[];
  packageManagers: PackageManager[];
  hasGit: boolean;
  routeFiles: string[];
}

export interface EndpointConfig {
  method: HttpMethod;
  path: string;
}

export interface IdorTargetConfig {
  method: HttpMethod;
  pathTemplate: string;
  ownerBResourceId: string;
}

export interface FuzzEndpointConfig {
  method: HttpMethod;
  path: string;
  sampleValidBody: Record<string, unknown>;
}

export interface WebhookEndpointConfig {
  provider: 'paystack' | 'stripe' | 'flutterwave';
  path: string;
}

export interface RateLimitEndpointConfig {
  method: HttpMethod;
  path: string;
  burstCount: number;
}

export interface AuthUserConfig {
  tokenEnvVar: string;
  resourceId?: string;
}

export interface DynamicAuthConfig {
  strategy: 'bearer' | 'cookie' | 'header';
  headerName?: string;
  cookieName?: string;
  userA?: AuthUserConfig;
  userB?: AuthUserConfig;
}

export interface StaticConfig {
  ignorePaths: string[];
  publicEndpointsAllowlist: string[];
}

export interface DynamicConfig {
  enabled: boolean;
  auth?: DynamicAuthConfig;
  protectedEndpoints: EndpointConfig[];
  idorTargets: IdorTargetConfig[];
  profileUpdateEndpoint?: EndpointConfig;
  fuzzEndpoints: FuzzEndpointConfig[];
  webhookEndpoints: WebhookEndpointConfig[];
  rateLimitEndpoints: RateLimitEndpointConfig[];
}

export interface CodlensConfig {
  projectName: string;
  targetDir: string;
  baseUrl?: string;
  static: StaticConfig;
  dynamic: DynamicConfig;
}

export interface SafetyGuardOptions {
  allowNonLocal?: boolean;
  allowMutations?: boolean;
}

export interface SafetyCheckResult {
  allowed: boolean;
  normalizedHost: string;
  isLocal: boolean;
  reason?: string;
}

export interface AuditSummary {
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  verdict: ReadinessVerdict;
  exitCode: ExitCodeValue;
}

export interface AuditReport {
  tool: 'codlens';
  version: string;
  timestamp: string;
  projectName: string;
  targetDir: string;
  baseUrl?: string;
  detectedStack: DetectedStack;
  summary: AuditSummary;
  modules: ModuleResult[];
  findings: Finding[];
}
