# Codlens

**Codlens** is a standalone, read-only CLI audit test harness for AI-generated full-stack web applications. Point it at **any** local project folder (and optionally its running local/staging server) to run both **static source-code analysis** and **dynamic HTTP security probes**, generating learning-first reports with redacted evidence, `curl` reproductions, and AI-ready fix prompts.

> Codlens never modifies files inside target repositories and requires zero paid APIs or mandatory browser installs.

---

## Quick Start (Under 2 Minutes)

### 1. Install & Build Codlens (One-Time Setup)

```bash
cd ~/projects/codlens
npm install
npm run build

# Optional: expose `codlens` globally in your shell
npm link
```

*(If you skip `npm link`, replace `codlens` below with `node ./dist/cli.js`.)*

### 2. Run a Fast Static-Only Audit on Any Project

```bash
codlens run --target ../my-ai-app --static-only
```

Reports are written to `./reports/<project-name>-<YYYYMMDD-HHmmss>/`:
- `CODLENS_REPORT.md` — Executive summary, readiness verdict, plain-English explanations, and AI fix prompts.
- `codlens-report.json` — Machine-readable report for CI/CD or agent follow-up.

### 3. Onboard a Project for Full Static + Dynamic Auditing

1. **Generate a starter config** (read-only scan of routes in your target repo):
   ```bash
   codlens init --target ../my-ai-app --base-url http://localhost:3000 --output ./my-ai-app.codlens.json
   ```
2. **Fill in two non-admin test accounts & IDOR target IDs** in `my-ai-app.codlens.json` (tokens are always referenced by environment variable name, never hardcoded):
   ```bash
   export CODLENS_USER_A_TOKEN="<user-a-session-or-jwt>"
   export CODLENS_USER_B_TOKEN="<user-b-session-or-jwt>"
   ```
3. **Start your target app locally**, then run the full audit:
   ```bash
   codlens run --config ./my-ai-app.codlens.json
   ```

---

## CLI Reference

| Command | Description |
| :--- | :--- |
| `codlens init --target <path> [--output <file>] [--base-url <url>]` | Scans the target repo read-only and generates a starter `codlens.config.json`. |
| `codlens run --config <path> [options]` | Runs static and dynamic audits using a project config file. |
| `codlens run --target <path> --static-only` | Runs static source-code checks without needing a config file or running server. |
| `codlens self-test` | Runs the built-in Vitest suite against `fixtures/vulnerable-canary` and `fixtures/hardened-canary`. |

### Useful `codlens run` Options
- `--static-only` — Skip dynamic HTTP probes.
- `--base-url <url>` — Override `baseUrl` from config.
- `--out-dir <dir>` — Output directory for reports (default: `./reports`).
- `--allow-non-local` — Explicitly allow dynamic probes against a non-local staging URL.
- `--browser` — Enable optional lazy-loaded Playwright browser inspection.
- `--skip-deps` — Skip `npm audit` dependency check.

---

## What Codlens Checks

### Static Audit Modules (`src/checks/static/`)
- **`STAT-001` Secret & Key Leakage:** Hardcoded API keys (`sk_live_`, `sk_test_`, `sk-ant-`, `AIza`, `ghp_`, DB passwords, high-entropy secrets), `.env` tracked in Git or missing from `.gitignore`, and `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` secret leaks. All secrets are masked to at most the first 4 characters.
- **`STAT-002` Injection Risks:** String-interpolated/concatenated SQL, dynamic `exec`/`spawn`/`subprocess`, `eval()`/`new Function()`, and unsanitized `dangerouslySetInnerHTML`.
- **`STAT-003` Missing Route Auth Heuristics:** Mutating and `/admin` routes in Next.js (`app/api`, `pages/api`), Express/Fastify/Hono, and FastAPI/Flask without server-side auth middleware/checks.
- **`STAT-004` Client-Trusted Payments & Webhooks:** Paystack/Stripe/Flutterwave webhooks missing cryptographic signature verification, and checkout handlers trusting `price`/`amount` from `req.body`.
- **`STAT-005` Missing Input Validation:** `req.body` / `request.json()` flowing directly into writes without schema or type validation.
- **`STAT-006` Upload & LLM Spend Safeguards:** File uploads lacking size/MIME limits and LLM SDK calls lacking `max_tokens` or rate limiting.
- **`STAT-007` BaaS Security Rules:** Open `firestore.rules` (`if true`) and Supabase SQL tables created without `ENABLE ROW LEVEL SECURITY`.
- **`STAT-DEPS` Dependency Audit:** Wraps `npm audit --json --omit=dev` gracefully when `package-lock.json` is present.

### Dynamic Audit Modules (`src/checks/dynamic/`)
- **`DYN-001` Unauthenticated Access:** Calls `protectedEndpoints` with no credentials (expects `401`/`403`; flags `200`/`201`/`500`).
- **`DYN-002` IDOR / Cross-Tenant Probe:** Authenticates as `userA` and requests `userB`'s resources (expects `403`/`404`).
- **`DYN-003` Mass Assignment & Role Escalation:** Sends `{ role: "admin", isAdmin: true, plan: "pro", balance: 999999 }` as `userA` and checks response + re-fetched profile.
- **`DYN-004` Input Fuzzing & Negative Values:** Sends malformed JSON, negative `quantity`/`amount`, and 10KB wrong-type payloads.
- **`DYN-005` Webhook Forgery Probe:** Sends unsigned and forged-signature Paystack/Stripe/Flutterwave payloads.
- **`DYN-006` Error & Stack Trace Leakage:** Checks error responses for JS/Python stack traces, raw SQL errors, and server OS paths (`/home/`, `/Users/`, `/usr/`, `/app/`, `C:\`).
- **`DYN-007` Rate Limiting Check:** Sends a controlled burst to login/AI endpoints expecting HTTP `429` or `Retry-After`.
- **`DYN-008` CORS & Security Headers:** Flags credentialed wildcard/reflected CORS and missing baseline headers (`X-Content-Type-Options`, `X-Frame-Options` / CSP).

---

## Safety Guardrails & Exit Codes

- **Loopback-Only by Default:** Dynamic tests only allow `localhost`, `127.0.0.1`, `0.0.0.0`, and `::1` (including bracketed `http://[::1]:<port>`). Any other host is refused with exit code `2` unless `--allow-non-local` is passed.
- **Non-Local Mutation Lock:** Even with `--allow-non-local`, mutating HTTP requests (`POST`, `PUT`, `PATCH`, `DELETE`) against non-local hosts are refused unless `ALLOW_MUTATIONS=true` is explicitly set in the environment.
- **Deterministic Exit Codes:**
  - `0` — Pass (`LAUNCH READY WITH NOTES` — zero `CRITICAL` and zero `HIGH` findings)
  - `1` — Audit failed (`BLOCKED FOR LAUNCH` or `NEEDS HARDENING` — `CRITICAL` or `HIGH` findings detected)
  - `2` — Harness or configuration error (invalid config, unreachable target server, or safety guard block)

---

## WSL2 Setup Notes

1. **Keep repositories on the native Linux filesystem:** Store both `codlens/` and target projects under `~/projects/` rather than `/mnt/c/` for fast file scanning, reliable POSIX permissions, and clean LF line endings.
2. **Optional `--browser` mode (Playwright):** Codlens builds and runs all core static/dynamic checks and tests without Playwright installed. If you want `--browser` runtime inspection in WSL2, install Playwright and Chromium system libraries once:
   ```bash
   npm install -D playwright
   npx playwright install --with-deps chromium
   ```
3. **Testing across the Windows / WSL2 boundary:** If your target dev server runs on Windows while Codlens runs in WSL2 (or vice versa), enable mirrored networking in `C:\Users\<YourWindowsUser>\.wslconfig`:
   ```ini
   [wsl2]
   networkingMode=mirrored
   ```
   Then restart WSL (`wsl --shutdown` in PowerShell) so `localhost`, `127.0.0.1`, and `[::1]` resolve identically across Windows and WSL2.
