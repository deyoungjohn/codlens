import crypto from 'node:crypto';
import http from 'node:http';

const ITEM_PRICES = {
  item_1: 1000,
  item_2: 2500,
};

// Parameterized SQL helper (STAT-002 safe)
export function safeFindUser(db, userId) {
  return db.query('SELECT id, email, role FROM users WHERE id = $1', [userId]);
}

// Restricted upload + capped LLM call (STAT-006 safe)
export function setupSafeUpload(multer) {
  return multer({
    dest: '/tmp/uploads',
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (_req, file, cb) => {
      const allowedTypes = ['image/png', 'image/jpeg', 'application/pdf'];
      cb(null, allowedTypes.includes(file.mimetype));
    },
  });
}

export async function generateSafeSummary(openai, prompt) {
  return openai.chat.completions.create({
    model: 'gpt-4o-mini',
    max_tokens: 256,
    messages: [{ role: 'user', content: prompt }],
  });
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(Buffer.from(c)));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

function authenticate(req, tokens) {
  const header = req.headers.authorization ?? '';
  if (!header.startsWith('Bearer ')) return null;
  const token = header.slice('Bearer '.length);
  return tokens[token] ?? null;
}

/**
 * Hardened HTTP server that fixes every vulnerability from vulnerable-canary.
 */
export function createHardenedServer(options = {}) {
  const userAToken = options.userAToken ?? 'hardened_user_a_token';
  const userBToken = options.userBToken ?? 'hardened_user_b_token';
  const webhookSecret = options.webhookSecret ?? 'hardened_webhook_secret';

  const tokens = {
    [userAToken]: { id: 'user_a', role: 'user' },
    [userBToken]: { id: 'user_b', role: 'user' },
  };

  const users = {
    user_a: { id: 'user_a', name: 'Alice', email: 'a@example.com', role: 'user', isAdmin: false, plan: 'free', balance: 0 },
    user_b: { id: 'user_b', name: 'Bob', email: 'b@example.com', role: 'user', isAdmin: false, plan: 'free', balance: 0 },
  };

  const orders = {
    order_a_123: { id: 'order_a_123', userId: 'user_a', itemId: 'item_1', quantity: 1, total: 1000 },
    order_b_456: { id: 'order_b_456', userId: 'user_b', itemId: 'item_1', quantity: 2, total: 2000 },
  };

  let loginAttempts = 0;

  return http.createServer(async (req, res) => {
    // Baseline security headers & restricted CORS (DYN-008 safe)
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');

    if (req.method === 'OPTIONS') {
      res.statusCode = 204;
      res.end();
      return;
    }

    const url = req.url ?? '/';
    const user = authenticate(req, tokens);

    // DYN-001 safe: requires authentication + admin role
    if (req.method === 'GET' && url === '/api/admin/users') {
      if (!user) {
        res.statusCode = 401;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }
      if (user.role !== 'admin') {
        res.statusCode = 403;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Forbidden' }));
        return;
      }
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(Object.values(users)));
      return;
    }

    // DYN-002 safe: enforces ownership check (order.userId === user.id)
    if (req.method === 'GET' && url.startsWith('/api/orders/')) {
      if (!user) {
        res.statusCode = 401;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }
      const id = decodeURIComponent(url.slice('/api/orders/'.length));
      const order = orders[id];
      if (!order) {
        res.statusCode = 404;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Not found' }));
        return;
      }
      if (order.userId !== user.id) {
        res.statusCode = 403;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Forbidden' }));
        return;
      }
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(order));
      return;
    }

    // DYN-003 safe: strict field allowlist prevents mass assignment
    if (req.method === 'PATCH' && url === '/api/profile') {
      if (!user) {
        res.statusCode = 401;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }
      const raw = await readBody(req);
      let body;
      try {
        body = JSON.parse(raw);
      } catch {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Invalid JSON payload' }));
        return;
      }
      if (typeof body.name === 'string' && body.name.length <= 100) {
        users[user.id].name = body.name;
      }
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(users[user.id]));
      return;
    }

    if (req.method === 'GET' && url === '/api/profile') {
      if (!user) {
        res.statusCode = 401;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(users[user.id]));
      return;
    }

    // DYN-004 & DYN-006 safe: strict input validation + server-side price lookup + sanitized errors
    if (req.method === 'POST' && url === '/api/orders') {
      if (!user) {
        res.statusCode = 401;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }
      const raw = await readBody(req);
      let body;
      try {
        body = JSON.parse(raw);
      } catch {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Malformed JSON body' }));
        return;
      }

      if (
        typeof body.itemId !== 'string' ||
        !(body.itemId in ITEM_PRICES) ||
        !Number.isInteger(body.quantity) ||
        body.quantity <= 0 ||
        body.quantity > 100
      ) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Invalid itemId or quantity' }));
        return;
      }

      const total = ITEM_PRICES[body.itemId] * body.quantity;
      res.statusCode = 201;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ id: 'order_new', userId: user.id, itemId: body.itemId, quantity: body.quantity, total }));
      return;
    }

    // DYN-005 safe: cryptographic HMAC-SHA512 signature verification with timingSafeEqual
    if (req.method === 'POST' && url === '/api/webhooks/paystack') {
      const raw = await readBody(req);
      const sigHeader = req.headers['x-paystack-signature'];
      if (typeof sigHeader !== 'string' || !sigHeader) {
        res.statusCode = 401;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Missing webhook signature' }));
        return;
      }

      const expected = crypto.createHmac('sha512', webhookSecret).update(raw).digest('hex');
      const sigBuf = Buffer.from(sigHeader, 'utf8');
      const expBuf = Buffer.from(expected, 'utf8');
      if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
        res.statusCode = 401;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Invalid webhook signature' }));
        return;
      }

      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ received: true }));
      return;
    }

    // DYN-007 safe: rate limiting with HTTP 429 + Retry-After
    if (req.method === 'POST' && url === '/api/auth/login') {
      await readBody(req);
      loginAttempts += 1;
      if (loginAttempts > 5) {
        res.statusCode = 429;
        res.setHeader('Retry-After', '60');
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Too many login attempts' }));
        return;
      }
      res.statusCode = 401;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Invalid credentials' }));
      return;
    }

    res.statusCode = 404;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Not found' }));
  });
}
