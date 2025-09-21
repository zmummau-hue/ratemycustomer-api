import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import xss from 'xss';
import { pool } from './db.js';

const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '1mb' }));

const JWT_SECRET = process.env.JWT_SECRET || 'change_me';

// ---------- helpers ----------
const sign = (u) =>
  jwt.sign({ id: u.id, role: u.role, username: u.username }, JWT_SECRET, { expiresIn: '12h' });

const auth = (req, res, next) => {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(t, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

const requireRole = (...roles) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'Auth required' });
  if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
  next();
};

const createLimiter = rateLimit({
  windowMs: 60_000,
  max: 20,
  standardHeaders: true,
});

// ---------- health ----------
app.get('/', (_req, res) => res.send('API OK'));

// ---------- first user -> OWNER ----------
app.post('/auth/register-owner', async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT 1 FROM users WHERE role='owner' LIMIT 1");
    if (rows.length) return res.status(403).json({ error: 'Owner already exists' });

    const { email, username, password } = req.body || {};
    if (!email || !username || !password)
      return res.status(400).json({ error: 'email, username, password required' });

    const hash = await bcrypt.hash(password, 11);
    const q = await pool.query(
      `INSERT INTO users (email, username, password_hash, role)
       VALUES ($1,$2,$3,'owner')
       RETURNING id, email, username, role`,
      [email.trim(), username.trim(), hash]
    );
    res.json({ user: q.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

// ---------- login ----------
app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const u = await pool.query('SELECT * FROM users WHERE username=$1 AND is_active=TRUE', [username]);
    if (!u.rowCount) return res.status(401).json({ error: 'Invalid credentials' });

    const row = u.rows[0];
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    res.json({ token: sign(row), user: { id: row.id, username: row.username, role: row.role } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

// ---------- user management (owner/admin) ----------
const isOwner = (req) => req.user?.role === 'owner';

app.get('/users', auth, requireRole('owner', 'admin'), async (_req, res) => {
  const r = await pool.query(
    'SELECT id, email, username, role, is_active, created_at FROM users ORDER BY created_at DESC'
  );
  res.json(r.rows);
});

app.post('/users', auth, requireRole('owner', 'admin'), async (req, res) => {
  try {
    const { email, username, password, role } = req.body || {};
    const allowed = ['admin', 'moderator', 'employee'];
    if (!allowed.includes(role)) return res.status(400).json({ error: 'Invalid role' });
    if (!isOwner(req) && role === 'admin')
      return res.status(403).json({ error: 'Only owner can create admin' });
    if (!email || !username || !password)
      return res.status(400).json({ error: 'email, username, password required' });

    const hash = await bcrypt.hash(password, 11);
    const q = await pool.query(
      `INSERT INTO users (email, username, password_hash, role)
       VALUES ($1,$2,$3,$4)
       RETURNING id, email, username, role, created_at`,
      [email.trim(), username.trim(), hash, role]
    );
    res.json(q.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

app.patch('/users/:id/role', auth, requireRole('owner', 'admin'), async (req, res) => {
  try {
    const { role } = req.body || {};
    const allowed = ['admin', 'moderator', 'employee'];
    if (!allowed.includes(role)) return res.status(400).json({ error: 'Invalid role' });
    if (!isOwner(req) && role === 'admin')
      return res.status(403).json({ error: 'Only owner can assign admin' });

    const u = await pool.query('SELECT role FROM users WHERE id=$1', [req.params.id]);
    if (!u.rowCount) return res.status(404).json({ error: 'User not found' });
    if (u.rows[0].role === 'owner') return res.status(403).json({ error: 'Cannot change owner role' });

    await pool.query('UPDATE users SET role=$1 WHERE id=$2', [role, req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

app.patch('/users/:id/active', auth, requireRole('owner', 'admin'), async (req, res) => {
  try {
    const { is_active } = req.body || {};
    const u = await pool.query('SELECT role FROM users WHERE id=$1', [req.params.id]);
    if (!u.rowCount) return res.status(404).json({ error: 'User not found' });
    if (u.rows[0].role === 'owner') return res.status(403).json({ error: 'Cannot deactivate owner' });

    await pool.query('UPDATE users SET is_active=$1 WHERE id=$2', [!!is_active, req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

// ---------- reviews ----------
app.post(
  '/reviews',
  createLimiter,
  auth,
  requireRole('employee', 'moderator', 'admin', 'owner'),
  async (req, res) => {
    try {
      let { first_name, store, category, subcategory, date_of_interaction, rating, content } =
        req.body || {};

      if (!first_name || !store || !content)
        return res.status(400).json({ error: 'Missing fields' });

      if (String(first_name).trim().split(/\s+/).length > 1)
        return res.status(400).json({ error: 'First name only' });

      first_name = xss(String(first_name).trim().split(/\s+/)[0]);
      store = xss(String(store).trim());
      content = xss(String(content).trim());
      rating = Number(rating || 3);

      const q = await pool.query(
        `INSERT INTO reviews
          (first_name, store, category, subcategory, date_of_interaction, rating, content, status, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8)
         RETURNING *`,
        [
          first_name,
          store,
          category || null,
          subcategory || null,
          date_of_interaction || null,
          rating,
          content,
          req.user.id,
        ]
      );

      await pool.query(
        'INSERT INTO audit_logs (review_id, action, actor_id, note) VALUES ($1,$2,$3,$4)',
        [q.rows[0].id, 'create', req.user.id, null]
      );

      res.json(q.rows[0]);
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'server error' });
    }
  }
);

// public list (approved only)
app.get('/reviews', async (req, res) => {
  const { category, subcategory } = req.query;
  const params = [];
  let sql = `SELECT id, first_name, store, category, subcategory,
                    date_of_interaction, rating, content, created_at
             FROM reviews WHERE status='approved'`;
  if (category) {
    params.push(category);
    sql += ` AND category=$${params.length}`;
  }
  if (subcategory) {
    params.push(subcategory);
    sql += ` AND subcategory=$${params.length}`;
  }
  sql += ' ORDER BY created_at DESC LIMIT 200';
  const r = await pool.query(sql, params);
  res.json(r.rows);
});

// ---------- moderation ----------
app.get('/moderation/pending', auth, requireRole('moderator', 'admin', 'owner'), async (_req, res) => {
  const r = await pool.query(
    `SELECT r.*, u.username AS submitted_by
     FROM reviews r LEFT JOIN users u ON r.created_by = u.id
     WHERE r.status='pending' ORDER BY r.created_at ASC`
  );
  res.json(r.rows);
});

app.post('/moderation/:id/approve', auth, requireRole('moderator', 'admin', 'owner'), async (req, res) => {
  await pool.query("UPDATE reviews SET status='approved' WHERE id=$1", [req.params.id]);
  await pool.query(
    'INSERT INTO audit_logs (review_id, action, actor_id, note) VALUES ($1,$2,$3,$4)',
    [req.params.id, 'approve', req.user.id, req.body?.note || null]
  );
  res.json({ ok: true });
});

app.post('/moderation/:id/reject', auth, requireRole('moderator', 'admin', 'owner'), async (req, res) => {
  await pool.query("UPDATE reviews SET status='rejected' WHERE id=$1", [req.params.id]);
  await pool.query(
    'INSERT INTO audit_logs (review_id, action, actor_id, note) VALUES ($1,$2,$3,$4)',
    [req.params.id, 'reject', req.user.id, req.body?.note || null]
  );
  res.json({ ok: true });
});

// ---------- start ----------
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log('API on :' + PORT));

