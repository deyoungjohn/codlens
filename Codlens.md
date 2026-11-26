# HANDOFF.md — Codlens (Full-Stack AI Project Audit Test Harness)

> **Audience:** Autonomous Coding Agent (Antigravity)  
> **Owner:** Project Author  
> **Environment:** Windows + WSL2 (Linux filesystem, e.g., `~/projects/`)  
> **Goal:** Build **Codlens**, a reusable, standalone CLI test harness that audits AI-generated full-stack web applications for security vulnerabilities, broken access control, leaked secrets, poor error handling, and production readiness—and outputs clear, educational audit reports.

---

## 1. Objective & Context

I build full-stack web applications with AI across different repositories. Because AI coding tools optimize for the "happy path," generated apps frequently ship with silent security flaws (missing server-side auth, IDOR vulnerabilities, exposed secret keys, unvalidated inputs, unsafe payment flows, or leaking stack traces).

Your mission is to build **Codlens**, a **standalone, reusable Audit Test Harness** in its own workspace/repository (`codlens/`) inside WSL2 that I can point at **any** local project folder (and its running local/staging server) to automatically inspect both the **source code (static audit)** and the **running application (dynamic audit)**.

Every audit must also act as a **code-literacy learning tool**: findings must explain *where* the issue lives, *how* an attacker or edge case breaks it, and *how* to fix it cleanly.

---

## 2. Agent Directives & Safety Guardrails

Follow these rules strictly while building and running Codlens:

1. **Read-Only on Target Repos:** Codlens MUST NEVER modify source files inside a target project being audited. It only reads files and writes reports to an output directory (default: `./reports/<project-name>-<timestamp>/`).
2. **Production Safety Lock:** Dynamic tests MUST refuse to run against live production URLs unless the user explicitly passes `--allow-non-local` (and even then, refuse any destructive `DELETE`/`POST` mutations unless `ALLOW_MUTATIONS=true` is explicitly configured). Default allowed hosts: `localhost`, `127.0.0.1`, `0.0.0.0`, and `::1` (IPv6 loopback, which Node.js on Linux/WSL frequently resolves `localhost` to by default). Normalize bracketed IPv6 hostnames (`[::1]`) cleanly when validating URLs.
3. **Zero External Paid Dependencies:** Codlens must work 100% locally out of the box in WSL2 using Node.js + TypeScript without requiring paid APIs or mandatory OS-level binary installs. (Optional hooks for `gitleaks` or `semgrep` may be supported if detected on `$PATH`, with pure TypeScript fallbacks always enabled.)
4. **WSL2 & Linux Path Hygiene:** Assume both `codlens/` and target repositories live on the native Linux filesystem (`~/...`, not `/mnt/c/...`). Use `path.resolve` / `path.posix` cleanly, avoid Windows-only shell assumptions, and handle POSIX permissions and LF line endings gracefully.
5. **Deterministic Exit Codes:**
   - `0`: Pass (no `CRITICAL` or `HIGH` issues)
   - `1`: Audit failed (`CRITICAL` or `HIGH` findings detected)
   - `2`: Harness/configuration error (e.g., target server unreachable, invalid config)
6. **Self-Verify Before Finishing:** You must build an intentionally vulnerable dummy full-stack app (`fixtures/vulnerable-canary/`) and prove via automated tests that Codlens catches every planted vulnerability, and that it passes cleanly against a fixed version (`fixtures/hardened-canary/`).

---

## 3. Recommended Tech Stack for Codlens

- **Runtime:** Node.js (LTS in WSL2) + TypeScript (`tsx` or compiled `tsc`)
- **CLI Parsing:** `commander` (or lightweight custom parser), exposing the `codlens` binary via `package.json` `"bin"`
- **Test/Assertion Runner:** `vitest` (for unit/self-tests of the harness itself)
- **Dynamic HTTP & Browser Inspection:** Native `fetch` for API probing + `playwright` (strictly optional and **lazy-loaded via dynamic `import()`** only when `--browser` is passed, so `npm install`, `npm run build`, and `npm test` succeed without requiring Chromium Linux system libraries via `npx playwright install --with-deps chromium`; if `--browser` is invoked without Playwright/Chromium installed, exit gracefully with setup instructions)
- **Config Validation:** `zod`

---

## 4. Target Directory Layout

Create the following modular structure inside `codlens/`:

```text
codlens/
├── package.json                   # Exposes `"bin": { "codlens": "./dist/cli.js" }`
├── tsconfig.json
├── README.md                      # Clear usage guide for the human owner (including WSL2 notes)
├── src/
│   ├── cli.ts                     # CLI entrypoint (`codlens run`, `codlens init`, `codlens self-test`)
│   ├── types.ts                   # Finding, Severity, ModuleResult, CodlensConfig interfaces
│   ├── core/
│   │   ├── detector.ts            # Auto-detects target stack (Next.js, Express, FastAPI, Supabase, etc.)
│   │   ├── config-loader.ts       # Loads & validates `codlens.config.json` with Zod
│   │   ├── runner.ts              # Orchestrates static + dynamic modules & aggregates scores
│   │   └── safety-guard.ts        # Enforces localhost/loopback-only (`::1` included) & non-destructive defaults
│   ├── checks/
│   │   ├── static/
│   │   │   ├── secrets-scan.ts    # Hardcoded keys, .env in git, NEXT_PUBLIC_/VITE_ secret leaks
│   │   │   ├── sql-cmd-scan.ts    # String-interpolated SQL, raw exec/spawn with user input
│   │   │   ├── auth-routes.ts     # Heuristics for unprotected API routes & missing middleware
│   │   │   ├── validation-scan.ts # Checks for schema validation (Zod/Joi/Pydantic) on handlers
│   │   │   ├── payment-scan.ts    # Flags client-trusted prices or unverified Paystack/Stripe webhooks
│   │   │   └── deps-audit.ts      # Wraps `npm audit` / `pip-audit` gracefully if lockfiles exist
│   │   └── dynamic/
│   │       ├── auth-bypass.ts     # Unauthenticated access checks (expects 401/403, flags 200/500)
│   │       ├── idor-probe.ts      # Cross-user access checks (User A token hitting User B resource)
│   │       ├── role-escalation.ts # Attempts privilege flags (`isAdmin: true`, `role: "admin"`) in payloads
│   │       ├── input-fuzzer.ts    # Malformed JSON, wrong types, negative numbers, oversized payloads
│   │       ├── webhook-probe.ts   # Sends unsigned/forged Paystack & Stripe webhook requests
│   │       ├── error-leakage.ts   # Triggers 400/404/500 and scans for stack traces, SQL, or OS paths
│   │       ├── rate-limit.ts      # Burst test on login/AI endpoints to verify 429 throttling
│   │       └── headers-cors.ts    # Checks security headers & overly permissive CORS (`*` + credentials)
│   └── reporters/
│       ├── json-reporter.ts       # Machine-readable `codlens-report.json`
│       ├── markdown-reporter.ts   # Human-readable `CODLENS_REPORT.md` with learning explanations
│       └── console-reporter.ts    # Clean terminal summary table
├── fixtures/
│   ├── vulnerable-canary/         # Small Express/Node app with intentional flaws for self-testing
│   └── hardened-canary/           # Fixed version of the canary app that must pass with 0 critical/high
└── tests/
    └── harness.test.ts            # End-to-end Vitest suite verifying detection accuracy
```

---

## 5. Detailed Audit Specifications

### 5.1 Target Stack Auto-Detection (`src/core/detector.ts`)
When pointed at `<target-repo>`, automatically inspect files (ignoring `node_modules`, `.git`, `.next`, `dist`, `venv`, `__pycache__`) to classify:
- **Framework:** Next.js (`app/api` or `pages/api`), Express/Fastify/Hono, React/Vite, Python (FastAPI/Django/Flask)
- **Database / BaaS:** Prisma (`schema.prisma`), Drizzle, Supabase (`supabase/` or `@supabase/supabase-js`), Firebase (`firestore.rules`), MongoDB/Mongoose
- **Payment Providers:** Paystack, Stripe, Flutterwave
- **AI / LLM SDKs:** OpenAI, Anthropic, Google GenAI, Vercel AI SDK (used to flag endpoints that need rate limiting / spend caps)

### 5.2 Static Audit Modules (`src/checks/static/`)

| Check ID | Name | What to Detect | Default Severity |
| :--- | :--- | :--- | :--- |
| `STAT-001` | **Secret & Key Leakage** | Regex + entropy scan for API keys (`sk_live_`, `sk_test_`, `sk-ant-`, `AIza`, `ghp_`, JWT secrets, DB connection strings with passwords). Check if `.env` is tracked in `.git` or missing from `.gitignore`. Flag private/service-role keys prefixed with `NEXT_PUBLIC_`, `VITE_`, or `REACT_APP_`. | `CRITICAL` |
| `STAT-002` | **Injection Risks** | Template literals or string concatenation inside SQL queries (`.query(\`...${...}\`)`, `execute(f"...")`), `dangerouslySetInnerHTML`, `eval()`, or `child_process.exec` with dynamic input. | `CRITICAL` |
| `STAT-003` | **Missing Route Auth Heuristics** | Parse API route files (`app/api/**/route.ts`, Express routers, FastAPI endpoints) and flag mutating routes (`POST`, `PUT`, `PATCH`, `DELETE`) that contain no auth/session check helper (configurable allowlist for `/login`, `/register`, `/health`, `/webhook`). | `HIGH` |
| `STAT-004` | **Client-Trusted Payments & Webhooks** | Flag webhook handlers referencing Paystack (`x-paystack-signature`) or Stripe (`stripe-signature`) without signature verification (`createHmac` / `constructEvent`). Flag checkout handlers reading `price` or `amount` directly from `req.body` without DB lookup heuristics. | `CRITICAL` |
| `STAT-005` | **Missing Input Validation** | Flag route handlers reading `req.body` / `request.json()` directly into DB writes without a validation layer (`zod`, `joi`, `yup`, `pydantic`, or explicit type/range checks). | `MEDIUM` |
| `STAT-006` | **Upload & LLM Spend Safeguards** | Flag file upload endpoints missing MIME type or file size limits. Flag LLM SDK call sites lacking rate-limiting middleware or `max_tokens` caps. | `MEDIUM` |
| `STAT-007` | **BaaS Security Rules** | If `firestore.rules` contains `allow read, write: if true;` or Supabase SQL migrations create tables without `ENABLE ROW LEVEL SECURITY`, flag immediately. | `CRITICAL` |

### 5.3 Dynamic Audit Modules (`src/checks/dynamic/`)

Dynamic checks require a running local/staging target URL and a `codlens.config.json` defining test endpoints and two non-admin test accounts (`userA` and `userB`).

| Check ID | Name | Test Behavior | Pass / Fail Rule |
| :--- | :--- | :--- | :--- |
| `DYN-001` | **Unauthenticated Access** | Call every `protectedEndpoints` entry with **no** auth header/cookie. | **Pass:** `401` or `403`. **Fail (`CRITICAL`):** `200`/`201` or `500`. |
| `DYN-002` | **IDOR / Cross-Tenant Probe** | Authenticate as `userA` and attempt `GET`/`PUT`/`PATCH`/`DELETE` on resources owned by `userB` (defined in config). | **Pass:** `403` or `404`. **Fail (`CRITICAL`):** `200` returning `userB`'s data or mutating it. |
| `DYN-003` | **Mass Assignment & Role Escalation** | Send `PATCH`/`POST` as normal `userA` injecting `{ "role": "admin", "isAdmin": true, "plan": "pro", "balance": 999999 }`. Re-fetch user profile. | **Fail (`CRITICAL`):** Privileged fields change or return accepted state. |
| `DYN-004` | **Input Fuzzing & Negative Values** | Send malformed JSON, missing required fields, wrong data types, oversized strings (10KB), and negative numbers (`amount: -100`, `quantity: -5`) to configured endpoints. | **Pass:** `400` or `422`. **Fail (`HIGH`):** `500` crash or `200` accepting negative financial/quantity values. |
| `DYN-005` | **Webhook Forgery Probe** | Send fake `charge.success` / `checkout.session.completed` payloads to configured webhook endpoints with missing or invalid signatures. | **Pass:** `400`, `401`, or `403`. **Fail (`CRITICAL`):** `200`. |
| `DYN-006` | **Error & Stack Trace Leakage** | Trigger intentional bad requests and invalid routes. Inspect response bodies for stack traces (`at Object.<anonymous>`, `Traceback (most recent call last)`), absolute OS paths (`/home/`, `/Users/`, `/usr/`, `/app/`, `C:\`), or raw SQL errors. | **Fail (`MEDIUM`/`HIGH`):** Internal implementation details exposed in response body. |
| `DYN-007` | **Rate Limiting Check** | Send a controlled burst (e.g., 25 rapid requests) to configured auth/AI endpoints. | **Pass:** Receives `429` or `Retry-After` header. **Fail (`MEDIUM`):** All requests succeed without throttling. |
| `DYN-008` | **CORS & Security Headers** | Check `OPTIONS` / `GET` headers for `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`, plus presence of `X-Content-Type-Options`, `X-Frame-Options` / CSP. | **Fail (`HIGH`):** Credentialed wildcard CORS. **Warn (`LOW`):** Missing baseline security headers. |

---

## 6. Per-Project Configuration Schema (`codlens.config.json`)

Provide a `codlens init --target <path>` command that auto-generates a starter `codlens.config.json` by scanning routes in the target project.

```json
{
  "projectName": "my-ai-app",
  "targetDir": "../my-ai-app",
  "baseUrl": "http://localhost:3000",
  "static": {
    "ignorePaths": ["node_modules", ".next", "dist", "coverage"],
    "publicEndpointsAllowlist": ["/api/health", "/api/auth/login", "/api/auth/register"]
  },
  "dynamic": {
    "enabled": true,
    "auth": {
      "strategy": "bearer",
      "userA": {
        "tokenEnvVar": "CODLENS_USER_A_TOKEN",
        "resourceId": "order_a_123"
      },
      "userB": {
        "tokenEnvVar": "CODLENS_USER_B_TOKEN",
        "resourceId": "order_b_456"
      }
    },
    "protectedEndpoints": [
      { "method": "GET", "path": "/api/orders" },
      { "method": "GET", "path": "/api/profile" }
    ],
    "idorTargets": [
      {
        "method": "GET",
        "pathTemplate": "/api/orders/:id",
        "ownerBResourceId": "order_b_456"
      }
    ],
    "profileUpdateEndpoint": { "method": "PATCH", "path": "/api/profile" },
    "fuzzEndpoints": [
      {
        "method": "POST",
        "path": "/api/orders",
        "sampleValidBody": { "itemId": "item_1", "quantity": 1 }
      }
    ],
    "webhookEndpoints": [
      { "provider": "paystack", "path": "/api/webhooks/paystack" }
    ],
    "rateLimitEndpoints": [
      { "method": "POST", "path": "/api/auth/login", "burstCount": 25 }
    ]
  }
}
```

> **Note:** Auth tokens MUST be referenced via environment variable names (`tokenEnvVar`), never hardcoded into `codlens.config.json`.

---

## 7. Reporting Specification (Learning-First Output)

Every run must generate two files inside `reports/<projectName>-<YYYYMMDD-HHmmss>/`:

1. **`codlens-report.json`**: Complete structured data for CI/CD or agent follow-up.
2. **`CODLENS_REPORT.md`**: Clean executive summary + educational breakdown.

Each finding in both reports MUST include:
- `id`: Check ID (e.g., `DYN-002`)
- `severity`: `CRITICAL | HIGH | MEDIUM | LOW | INFO`
- `category`: `Secrets | Auth & Access Control | Injection | Validation & Payments | Production Safety`
- `location`: Exact `file:line` (static) or `METHOD /path` (dynamic)
- `evidence`: Redacted snippet or HTTP status/body excerpt (never print full secret values—mask all but first 4 chars!)
- `reproduction`: Exact `curl` command or steps so the owner can observe the bug firsthand
- `whyItMatters`: 2-3 sentences in plain English explaining the real-world impact (code-literacy builder)
- `howToFix`: Concrete remediation guidance + an AI-ready prompt snippet the owner can paste into their coding tool to fix the exact issue safely

Include an overall **Readiness Verdict** at the top of `CODLENS_REPORT.md`:
- `BLOCKED FOR LAUNCH` (any `CRITICAL` finding)
- `NEEDS HARDENING` (no `CRITICAL`, 1+ `HIGH` findings)
- `LAUNCH READY WITH NOTES` (only `MEDIUM`/`LOW` or zero findings)

---

## 8. Self-Verification Strategy (Canary Fixtures)

Before considering Codlens complete, build two tiny Express/Node fixtures inside `fixtures/`:

1. **`fixtures/vulnerable-canary/`** — Intentionally contains:
   - A fake hardcoded secret key + `NEXT_PUBLIC_SECRET_KEY`
   - A raw string-concatenated SQL pattern
   - An unprotected `GET /api/admin/users` route
   - An IDOR bug on `GET /api/orders/:id` (doesn't check `order.userId === req.user.id`)
   - A `PATCH /api/profile` vulnerable to `{ role: "admin" }` mass assignment
   - A `POST /api/orders` accepting negative `quantity` and returning raw stack traces on bad JSON
   - A `POST /api/webhooks/paystack` accepting unsigned payloads
   - Missing rate limiting on `POST /api/auth/login`

2. **`fixtures/hardened-canary/`** — Fixes every single flaw above cleanly.

Write an automated Vitest suite (`tests/harness.test.ts`) that:
- Boots `vulnerable-canary` on an ephemeral port (`127.0.0.1` or `::1`), runs the full static + dynamic harness, and asserts every planted check (`STAT-001` through `DYN-008`) triggers as expected.
- Boots `hardened-canary` on an ephemeral port, runs the full harness, and asserts **zero `CRITICAL` and zero `HIGH` findings** with exit code `0`.

---

## 9. Step-by-Step Execution Plan for Antigravity

Execute in this order, verifying each milestone before advancing:

- **Phase 1 — Scaffold & Core Engine:** Initialize `codlens/` inside WSL2 with TypeScript, Zod, Commander, and Vitest. Configure `"bin": { "codlens": "./dist/cli.js" }` in `package.json`, and implement `types.ts`, `safety-guard.ts` (including `::1` support), `detector.ts`, and `config-loader.ts`.
- **Phase 2 — Static Audit Suite:** Implement all `STAT-001` to `STAT-007` scanners with secret masking and line-number extraction.
- **Phase 3 — Dynamic Audit Suite:** Implement all `DYN-001` to `DYN-008` probes (including `/home/` Linux path-leak detection in `DYN-006`) with clean timeouts, retry handling, and `curl` reproduction generators. Keep `--browser` Playwright support strictly lazy-loaded.
- **Phase 4 — Reporters & CLI:** Implement `json-reporter.ts`, `markdown-reporter.ts`, `console-reporter.ts`, and wire up `codlens init`, `codlens run`, and `codlens self-test`.
- **Phase 5 — Canary Fixtures & Self-Test:** Build `vulnerable-canary` and `hardened-canary`, write `tests/harness.test.ts`, and run the entire suite until 100% green.
- **Phase 6 — Documentation:** Write a clear `README.md` showing exact commands for onboarding any new project in under 2 minutes, plus a brief WSL2 setup note (keeping repos in `~/`, optional `npx playwright install --with-deps chromium` for `--browser`, and `networkingMode=mirrored` in `.wslconfig` if testing servers across the Windows/WSL boundary).

---

## 10. Definition of Done

Hand work back to me only when all of the following are verified:

- [ ] `npm run build` compiles with zero TypeScript errors.
- [ ] `npm test` (Vitest end-to-end suite against both canary apps) passes 100% without requiring Playwright browser binaries installed.
- [ ] `codlens run --target ./fixtures/vulnerable-canary --static-only` exits with code `1` and produces valid `codlens-report.json` + `CODLENS_REPORT.md` with masked secrets.
- [ ] `codlens run` allows `http://localhost:<port>`, `http://127.0.0.1:<port>`, and `http://[::1]:<port>`, and refuses a non-localhost URL without `--allow-non-local` (exiting with code `2`).
- [ ] `codlens init --target ./fixtures/vulnerable-canary` generates a valid starter `codlens.config.json`.
- [ ] Sample generated `CODLENS_REPORT.md` is verified to be readable, accurate, and free of raw unmasked secrets.