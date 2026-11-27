# Codlens — Project Memory & Progress Log

> Running record of architectural decisions, build milestones, real-world calibration updates, and next steps for **Codlens**.

---

## Current Status

- **Version:** `0.1.0`
- **Branch:** `main`
- **Build & Test Health:** `npm run build` (0 TypeScript errors), `npm test` (**32/32** Vitest tests passing across 5 suites, no Playwright binary required).
- **Distribution Model:** Standalone, read-only CLI (`codlens`) run from its own repo against any local target project directory and/or local/staging server.

---

## Timeline & Changelog

### 2026-11-26 — Initial Build (Phases 1–6) (`115f9d9`)

Completed the full initial implementation from `Codlens.md`:

- **Phase 1 — Scaffold & Core Engine:**
  - Initialized ESM TypeScript (`NodeNext`), Commander, Zod, and Vitest with `"bin": { "codlens": "./dist/cli.js" }`.
  - Built `src/types.ts`, `src/core/safety-guard.ts` (loopback-only lock supporting `localhost`, `127.0.0.1`, `0.0.0.0`, and IPv6 `[::1]`, plus non-local mutation lock via `ALLOW_MUTATIONS=true`), `src/core/detector.ts`, and `src/core/config-loader.ts` (Zod validation + hardcoded-token rejection in `tokenEnvVar`).
- **Phase 2 — Static Audit Suite (`STAT-001`–`STAT-007`, `STAT-DEPS`):**
  - Implemented `secrets-scan.ts`, `sql-cmd-scan.ts`, `auth-routes.ts` (with bounded per-route handler windows), `payment-scan.ts`, `validation-scan.ts`, `safeguards-scan.ts`, `baas-rules-scan.ts`, `deps-audit.ts`, and shared `utils.ts` (secret masking to at most first 4 characters + Shannon entropy).
- **Phase 3 — Dynamic Audit Suite (`DYN-001`–`DYN-008`):**
  - Implemented `http-client.ts` (safety-guard enforcement on every request, timeouts, retries, env-var-backed auth, token-safe `curl` generator), `auth-bypass.ts`, `idor-probe.ts`, `role-escalation.ts`, `input-fuzzer.ts`, `webhook-probe.ts`, `error-leakage.ts` (including `/home/` Linux path leaks), `rate-limit.ts`, `headers-cors.ts`, and strictly lazy-loaded `browser-probe.ts`.
- **Phase 4 — Reporters, Core Runner & CLI:**
  - Built `src/core/runner.ts` (severity sorting, readiness verdicts, deterministic exit codes `0`/`1`/`2`), `json-reporter.ts`, `markdown-reporter.ts` (learning-first explanations + AI-ready fix prompts), `console-reporter.ts`, and wired `codlens init`, `codlens run`, and `codlens self-test` in `src/cli.ts`.
- **Phase 5 — Canary Fixtures & Self-Test:**
  - Built `fixtures/vulnerable-canary/` (all planted flaws across `STAT-001`–`STAT-007` and `DYN-001`–`DYN-008`) and `fixtures/hardened-canary/` (all flaws fixed).
  - Verified end-to-end in `tests/harness.test.ts` (vulnerable canary triggers all 15 checks with exit code `1`; hardened canary passes over IPv6 `[::1]` with 0 `CRITICAL`/`HIGH` and exit code `0`).
  - *Push Protection Note:* Switched the synthetic canary secret in `fixtures/vulnerable-canary/server.mjs` to `sk_test_canary99887766` and constructed `sk_live_` unit-test strings dynamically so GitHub Push Protection never blocks pushes.
- **Phase 6 — Documentation:**
  - Wrote `README.md` with <2-minute onboarding instructions, CLI reference, check summary, safety guardrails, and WSL2 notes (`~/projects/`, optional Playwright Chromium install, `networkingMode=mirrored`).

---

### 2026-11-26 — Real-World Static Calibration & Precision Improvements (`8b352e3`)

Ran `codlens run --static-only` against three real-world `pnpm` monorepos (`deyoungjohn/tally`, `deyoungjohn/openrail`, `deyoungjohn/ferry`) and implemented 7 targeted improvements based on observed false positives and detection gaps:

1. **Multi-Chain Public Address Exclusions (`STAT-001`):** Added `isPublicBlockchainAddress()` in `src/checks/static/secrets-scan.ts` to exclude public addresses across EVM (`0x<40 hex>`), Solana (Base58 mints/pubkeys), Sui/Aptos/Starknet (64-hex object IDs & `0x...::mod::Type` Move types), Bitcoin (`bc1`/`tb1`/`1`/`3`), Bitcoin Cash (CashAddr), Cosmos/IBC, TRON, NEAR, TON, Cardano, Polkadot/Substrate SS58, Stellar (`G...` public keys only), and XRP — while continuing to flag 64-hex private/signing key variables (`PRIVATE_KEY`, `signing_key`, etc.).
2. **Test, Mock & Dev-Script Filtering:** Added `isTestOrMockFile()` and `isDevScriptFile()` in `src/checks/static/utils.ts` and an opt-in `--include-tests` CLI flag (default: excluded from static scans).
3. **Tighter SQL & `eval()` Precision (`STAT-002`):** Required real SQL clause structure (`SELECT ... FROM`, `UPDATE <table> SET`, `INSERT INTO`, `DELETE FROM`), ignored `createHash`/`createHmac` `.update()`, and anchored `eval(` with `(?<![.\w$])eval\s*\(` so Playwright's `page.$eval()` is not flagged.
4. **Broader Auth Middleware Recognition (`STAT-003`):** Added Fastify `preHandler`, `verify*Auth`/`require*Auth` patterns, and configurable `static.customAuthHelpers` in `codlens.config.json`.
5. **Backend-Only, Deduplicated Payment Checks (`STAT-004`):** Skipped `.tsx`/frontend UI files, required `req.body`/`request.json()` rather than generic `data.amount`, and deduplicated findings per handler window.
6. **Monorepo Workspace Detection (`detector.ts`):** Extended `detectStack()` to inspect workspace `package.json` files (`apps/*`, `packages/*`, `services/*`, `libs/*`, `modules/*`).
7. **`pnpm audit` Support (`deps-audit.ts`):** Added `pnpm audit --json --prod` parsing alongside `npm audit --json --omit=dev`.

#### Calibration Results (Before → After)

| Target Repo | Stack Detected | Code Findings | `STAT-DEPS` (`pnpm audit`) |
| :--- | :--- | :---: | :---: |
| `tally` | `nextjs` → `nextjs` | `12 → 8` | `27` (2 CRITICAL, 6 HIGH, 19 MEDIUM) |
| `openrail` | `[]` → `nextjs` | `33 → 1` | `20` (7 HIGH, 13 MEDIUM) |
| `ferry` | `[]` → `fastify, react-vite` | `26 → 5` | `0` (clean) |

---

## Key Guardrails & Architectural Invariants

- **Read-Only on Target Repos:** Never write or mutate files inside a target repository; reports always go to `./reports/<project>-<YYYYMMDD-HHmmss>/` (or `--out-dir`).
- **No Raw Secrets in Reports or Config:** Static evidence masks secrets to at most 4 leading characters; dynamic `curl` reproductions reference `$ENV_VAR` names; `config-loader.ts` rejects raw JWTs/keys in `tokenEnvVar`.
- **Production Safety Lock:** Every dynamic HTTP call passes through `assertSafeRequestMethod()` in `src/core/safety-guard.ts`.
- **Zero Mandatory Browser Dependencies:** Playwright is dynamically imported only when `--browser` is passed.

---

## Upcoming / Backlog Ideas

- [ ] Run full **static + dynamic** (`DYN-001`–`DYN-008`) audits against real apps booted locally (`tally`, `openrail`, `ferry`).
- [ ] Add `pip-audit` execution in `deps-audit.ts` for Python projects with `requirements.txt`.
- [ ] Consider deduplicating repeated `STAT-DEPS` advisories per package (grouping multiple advisories for the same package like `next` into a single summary entry or keeping individual CVEs behind a `--verbose-deps` flag).
- [ ] Recognize SQL `IN (${marks})` safe `?`-placeholder generation patterns in `STAT-002` (e.g., `marks = ids.map(() => '?').join(',')`).
