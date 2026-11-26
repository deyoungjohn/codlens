import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runStaticAudit } from '../src/checks/static/index.js';
import { maskSecret } from '../src/checks/static/utils.js';
import { createDefaultConfig } from '../src/core/config-loader.js';
import { detectStack } from '../src/core/detector.js';

const tempDirs: string[] = [];

async function makeTempProject(files: Record<string, string>): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'codlens-static-'));
  tempDirs.push(dir);
  for (const [relPath, content] of Object.entries(files)) {
    const full = path.join(dir, relPath);
    await fs.mkdir(path.dirname(full), { recursive: true });
    await fs.writeFile(full, content, 'utf8');
  }
  return dir;
}

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()!;
    await fs.rm(dir, { recursive: true, force: true });
  }
});

describe('static audit suite (STAT-001 through STAT-007)', () => {
  it('masks secrets to at most first 4 characters', () => {
    expect(maskSecret('sk_live_1234567890abcdef')).toMatch(/^sk_l\*+$/);
    expect(maskSecret('sk_live_1234567890abcdef')).not.toContain('123456');
    expect(maskSecret('abc')).toBe('****');
  });

  it('STAT-001 detects hardcoded API keys, NEXT_PUBLIC_ secret leaks, and missing .env in .gitignore without exposing raw secrets', async () => {
    const rawKey = ['sk', 'live', '99887766554433221100aabb'].join('_');
    const dir = await makeTempProject({
      '.env': 'DATABASE_URL=postgres://user:pass@localhost/db\n',
      '.gitignore': 'node_modules/\n',
      'src/config.ts': [
        `export const STRIPE_KEY = "${rawKey}";`,
        `export const pubKey = process.env.NEXT_PUBLIC_SECRET_KEY;`,
      ].join('\n'),
    });

    const stack = await detectStack(dir);
    const config = createDefaultConfig(dir, { staticOnly: true });
    const modules = await runStaticAudit(config, stack, { skipDepsAudit: true });
    const stat001 = modules.find((m) => m.moduleId === 'STAT-001')!;

    expect(stat001.status).toBe('failed');
    expect(stat001.findings.length).toBeGreaterThanOrEqual(3);
    expect(stat001.findings.some((f) => f.title.includes('NEXT_PUBLIC_SECRET_KEY'))).toBe(true);
    expect(stat001.findings.some((f) => f.title.includes('.gitignore'))).toBe(true);

    // Ensure raw secret never leaks into any finding field
    const serialized = JSON.stringify(stat001.findings);
    expect(serialized).not.toContain(rawKey);
    expect(serialized).toContain('sk_l****');
  });

  it('STAT-002 detects SQL string interpolation, exec with interpolation, eval, and unsanitized dangerouslySetInnerHTML', async () => {
    const dir = await makeTempProject({
      'src/db.ts': [
        'export function getUser(db: any, id: string) {',
        '  return db.query(`SELECT * FROM users WHERE id = ${id}`);',
        '}',
        'export function runTool(exec: any, arg: string) {',
        '  return exec(`ls -la ${arg}`);',
        '}',
        'export function calc(expr: string) { return eval(expr); }',
      ].join('\n'),
      'src/Page.tsx': 'export const Page = ({ html }: { html: string }) => <div dangerouslySetInnerHTML={{ __html: html }} />;',
    });

    const stack = await detectStack(dir);
    const config = createDefaultConfig(dir, { staticOnly: true });
    const modules = await runStaticAudit(config, stack, { skipDepsAudit: true });
    const stat002 = modules.find((m) => m.moduleId === 'STAT-002')!;

    expect(stat002.status).toBe('failed');
    expect(stat002.findings).toHaveLength(4);
    expect(stat002.findings.every((f) => f.severity === 'CRITICAL')).toBe(true);
  });

  it('STAT-003 flags unprotected mutating and admin routes while allowing public allowlist & protected routes', async () => {
    const dir = await makeTempProject({
      'src/server.ts': [
        'app.post("/api/auth/login", (req, res) => res.json({ ok: true }));',
        'app.get("/api/admin/users", (req, res) => res.json([]));',
        'app.post("/api/orders", (req, res) => res.json({ created: true }));',
        'app.delete("/api/orders/:id", requireAuth, (req, res) => res.json({ deleted: true }));',
      ].join('\n'),
    });

    const stack = await detectStack(dir);
    const config = createDefaultConfig(dir, { staticOnly: true });
    const modules = await runStaticAudit(config, stack, { skipDepsAudit: true });
    const stat003 = modules.find((m) => m.moduleId === 'STAT-003')!;

    expect(stat003.status).toBe('failed');
    const titles = stat003.findings.map((f) => f.title);
    expect(titles.some((t) => t.includes('GET /api/admin/users'))).toBe(true);
    expect(titles.some((t) => t.includes('POST /api/orders'))).toBe(true);
    expect(titles.some((t) => t.includes('/api/auth/login'))).toBe(false);
    expect(titles.some((t) => t.includes('DELETE /api/orders/:id'))).toBe(false);
  });

  it('STAT-004 flags unverified Paystack webhooks and client-trusted checkout prices', async () => {
    const dir = await makeTempProject({
      'src/payments.ts': [
        'app.post("/api/webhooks/paystack", (req, res) => {',
        '  const event = req.body;',
        '  res.json({ received: true });',
        '});',
        'app.post("/api/checkout", requireAuth, (req, res) => {',
        '  const { amount } = req.body;',
        '  res.json({ charged: amount });',
        '});',
      ].join('\n'),
    });

    const stack = await detectStack(dir);
    const config = createDefaultConfig(dir, { staticOnly: true });
    const modules = await runStaticAudit(config, stack, { skipDepsAudit: true });
    const stat004 = modules.find((m) => m.moduleId === 'STAT-004')!;

    expect(stat004.status).toBe('failed');
    expect(stat004.findings).toHaveLength(2);
    expect(stat004.findings.every((f) => f.severity === 'CRITICAL')).toBe(true);
  });

  it('STAT-005 flags unvalidated request bodies written to DB', async () => {
    const dir = await makeTempProject({
      'src/profile.ts': [
        'app.patch("/api/profile", requireAuth, async (req, res) => {',
        '  const updated = await db.user.update({ where: { id: req.user.id }, data: req.body });',
        '  res.json(updated);',
        '});',
      ].join('\n'),
    });

    const stack = await detectStack(dir);
    const config = createDefaultConfig(dir, { staticOnly: true });
    const modules = await runStaticAudit(config, stack, { skipDepsAudit: true });
    const stat005 = modules.find((m) => m.moduleId === 'STAT-005')!;

    expect(stat005.findings.length).toBeGreaterThanOrEqual(1);
    expect(stat005.findings[0].severity).toBe('MEDIUM');
  });

  it('STAT-006 flags unrestricted uploads and uncapped LLM calls', async () => {
    const dir = await makeTempProject({
      'src/ai-upload.ts': [
        'const upload = multer({ dest: "/tmp/uploads" });',
        'export async function ask(prompt: string) {',
        '  return openai.chat.completions.create({ model: "gpt-4o", messages: [{ role: "user", content: prompt }] });',
        '}',
      ].join('\n'),
    });

    const stack = await detectStack(dir);
    const config = createDefaultConfig(dir, { staticOnly: true });
    const modules = await runStaticAudit(config, stack, { skipDepsAudit: true });
    const stat006 = modules.find((m) => m.moduleId === 'STAT-006')!;

    expect(stat006.findings).toHaveLength(2);
    expect(stat006.findings.every((f) => f.severity === 'MEDIUM')).toBe(true);
  });

  it('STAT-007 flags open Firestore rules and Supabase tables without RLS', async () => {
    const dir = await makeTempProject({
      'firestore.rules': 'rules_version = "2";\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} { allow read, write: if true; }\n  }\n}\n',
      'supabase/migrations/001_init.sql': 'CREATE TABLE orders (id uuid primary key, user_id uuid, amount int);\n',
    });

    const stack = await detectStack(dir);
    const config = createDefaultConfig(dir, { staticOnly: true });
    const modules = await runStaticAudit(config, stack, { skipDepsAudit: true });
    const stat007 = modules.find((m) => m.moduleId === 'STAT-007')!;

    expect(stat007.status).toBe('failed');
    expect(stat007.findings).toHaveLength(2);
    expect(stat007.findings.every((f) => f.severity === 'CRITICAL')).toBe(true);
  });

  it('passes cleanly with zero CRITICAL/HIGH findings on a hardened project', async () => {
    const dir = await makeTempProject({
      '.gitignore': 'node_modules/\n.env\n',
      'firestore.rules': 'rules_version = "2";\nmatch /users/{uid} { allow read, write: if request.auth != null && request.auth.uid == uid; }\n',
      'supabase/migrations/001_init.sql':
        'CREATE TABLE orders (id uuid primary key, user_id uuid);\nALTER TABLE orders ENABLE ROW LEVEL SECURITY;\n',
      'src/server.ts': [
        'import { z } from "zod";',
        'import crypto from "node:crypto";',
        'const orderSchema = z.object({ itemId: z.string(), quantity: z.number().int().positive() });',
        'const ITEM_PRICES: Record<string, number> = { item_1: 1000 };',
        'app.post("/api/orders", requireAuth, (req, res) => {',
        '  const parsed = orderSchema.safeParse(req.body);',
        '  if (!parsed.success) return res.status(400).json({ error: "Invalid input" });',
        '  const total = ITEM_PRICES[parsed.data.itemId] * parsed.data.quantity;',
        '  return db.query("SELECT * FROM orders WHERE id = $1", [parsed.data.itemId]);',
        '});',
        'app.post("/api/webhooks/paystack", (req, res) => {',
        '  const hash = crypto.createHmac("sha512", process.env.PAYSTACK_SECRET!).update(req.rawBody).digest("hex");',
        '  if (!crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(req.headers["x-paystack-signature"]))) return res.status(401).end();',
        '  res.json({ ok: true });',
        '});',
      ].join('\n'),
    });

    const stack = await detectStack(dir);
    const config = createDefaultConfig(dir, { staticOnly: true });
    const modules = await runStaticAudit(config, stack, { skipDepsAudit: true });
    const allFindings = modules.flatMap((m) => m.findings);
    const highOrCritical = allFindings.filter(
      (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH',
    );

    expect(highOrCritical).toEqual([]);
  });
});
