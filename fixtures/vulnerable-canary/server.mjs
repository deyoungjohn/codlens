import http from 'node:http';

// Intentional STAT-001 flaws: hardcoded fake secret + client-exposed secret env var
export const FAKE_PAYSTACK_SECRET = 'sk_test_canary99887766';
export const CLIENT_EXPOSED = process.env.NEXT_PUBLIC_SECRET_KEY;

// Intentional STAT-002 flaw: string-interpolated SQL helper
export function unsafeFindUser(db, userId) {
  return db.query(`SELECT * FROM users WHERE id = '${userId}'`);
}

// Intentional STAT-006 flaws: unrestricted upload + uncapped LLM call
export function setupUpload(multer) {
  return multer({ dest: '/tmp/uploads' });
}

export async function generateSummary(openai, prompt) {
  return openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [{ role: 'user', content: prompt }],
  });
}

// Route-style stubs so static scanners (STAT-003, STAT-004, STAT-005) inspect them cleanly
export function registerRouteHints(app, db) {
  app.get('/api/admin/users', (req, res) => res.json([]));
  app.post('/api/orders', (req, res) => {
    const { price, quantity } = req.body;
    return db.orders.create({ data: req.body, price, quantity });
  });
  app.patch('/api/profile', (req, res) => db.users.update({ data: req.body }));
  app.post('/api/webhooks/paystack', (req, res) => res.json({ ok: true }));
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(Buffer.from(c)));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

/**
 * Intentionally vulnerable HTTP server for Codlens self-verification.
 */
export function createVulnerableServer() {
  const users = {
    user_a: { id: 'user_a', email: 'a@example.com', role: 'user', isAdmin: false, plan: 'free', balance: 0 },
    user_b: { id: 'user_b', email: 'b@example.com', role: 'user', isAdmin: false, plan: 'free', balance: 0 },
  };
  const orders = {
    order_a_123: { id: 'order_a_123', userId: 'user_a', itemId: 'item_1', quantity: 1, total: 1000 },
    order_b_456: { id: 'order_b_456', userId: 'user_b', itemId: 'item_1', quantity: 2, total: 2000 },
  };

  return http.createServer(async (req, res) => {
    // Intentional DYN-008 flaw: credentialed wildcard CORS & missing security headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
      res.statusCode = 204;
      res.end();
      return;
    }

    const url = req.url ?? '/';

    // Intentional DYN-001 flaw: unprotected admin route
    if (req.method === 'GET' && url === '/api/admin/users') {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(Object.values(users)));
      return;
    }

    // Intentional DYN-002 flaw: IDOR — does not verify order.userId === req.user.id
    if (req.method === 'GET' && url.startsWith('/api/orders/')) {
      const id = decodeURIComponent(url.slice('/api/orders/'.length));
      const order = orders[id];
      if (!order) {
        res.statusCode = 404;
        res.end(JSON.stringify({ error: 'Order not found' }));
        return;
      }
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(order));
      return;
    }

    // Intentional DYN-003 flaw: mass assignment on PATCH /api/profile
    if (req.method === 'PATCH' && url === '/api/profile') {
      const raw = await readBody(req);
      const body = JSON.parse(raw || '{}');
      Object.assign(users.user_a, body);
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(users.user_a));
      return;
    }

    if (req.method === 'GET' && url === '/api/profile') {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(users.user_a));
      return;
    }

    // Intentional DYN-004 & DYN-006 flaws: accepts negative quantity, leaks stack trace & /home/ path on bad JSON
    if (req.method === 'POST' && url === '/api/orders') {
      const raw = await readBody(req);
      try {
        const body = JSON.parse(raw);
        const created = { id: 'order_new', userId: 'user_a', ...body };
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(created));
      } catch (err) {
        res.statusCode = 500;
        res.end(
          `SyntaxError: ${err.message}\n    at Object.<anonymous> (/home/dev/vulnerable-canary/server.mjs:98:24)`,
        );
      }
      return;
    }

    // Intentional DYN-005 flaw: accepts unsigned Paystack webhook payloads
    if (req.method === 'POST' && url === '/api/webhooks/paystack') {
      await readBody(req);
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ received: true, status: 'credited' }));
      return;
    }

    // Intentional DYN-007 flaw: no rate limiting on login
    if (req.method === 'POST' && url === '/api/auth/login') {
      await readBody(req);
      res.statusCode = 401;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Invalid credentials' }));
      return;
    }

    res.statusCode = 404;
    res.end(JSON.stringify({ error: 'Not found' }));
  });
}
