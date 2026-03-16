const express = require('express');
const bcrypt = require('bcryptjs');
const { pool } = require('../db/db');
const { generateToken, verifyToken } = require('../middleware/jwtUtils');

const router = express.Router();

// Helper: บันทึก log ลง DB ของ auth-service เอง
async function logEvent({ level, event, userId, ip, message, meta }) {
  try {
    await pool.query(
      `INSERT INTO logs (level, event, user_id, ip_address, message, meta)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [level, event, userId || null, ip || null, message || null,
       meta ? JSON.stringify(meta) : null]
    );
  } catch (e) {
    console.error('[auth-log]', e.message);
  }
}

// ── POST /api/auth/register ────────────────────────────────────────────
router.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.ip;

  if (!username || !email || !password)
    return res.status(400).json({ error: 'username, email, password are required' });

  if (password.length < 6)
    return res.status(400).json({ error: 'password ต้องมีอย่างน้อย 6 ตัวอักษร' });

  try {
    const exists = await pool.query(
      'SELECT id FROM users WHERE email = $1 OR username = $2',
      [email.toLowerCase().trim(), username.trim()]
    );
    if (exists.rows.length > 0)
      return res.status(409).json({ error: 'Email หรือ Username ถูกใช้งานแล้ว' });

    const password_hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (username, email, password_hash, role)
       VALUES ($1, $2, $3, 'member') RETURNING id, username, email, role, created_at`,
      [username.trim(), email.toLowerCase().trim(), password_hash]
    );
    const user = result.rows[0];

    await logEvent({
      level: 'INFO', event: 'REGISTER_SUCCESS',
      userId: user.id, ip,
      message: `New user registered: ${user.username}`,
      meta: { username: user.username, email: user.email }
    });

    res.status(201).json({
      message: 'สมัครสมาชิกสำเร็จ',
      user: { id: user.id, username: user.username, email: user.email, role: user.role }
    });

  } catch (err) {
    console.error('[auth] Register error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── POST /api/auth/login ────────────────────────────────────────────
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.ip;

  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });

  const normalizedEmail = email.toLowerCase().trim();

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
    const user = result.rows[0];

    const dummyHash = '$2b$10$invalidhashpadding000000000000000000000000000000000000';
    const isValid = await bcrypt.compare(password, user ? user.password_hash : dummyHash);

    if (!user || !isValid) {
      await logEvent({
        level: 'WARN', event: 'LOGIN_FAILED',
        userId: user?.id || null, ip,
        message: `Login failed: ${normalizedEmail}`,
        meta: { email: normalizedEmail }
      });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

    const token = generateToken({
      sub: user.id,
      email: user.email,
      username: user.username,
      role: user.role
    });

    await logEvent({
      level: 'INFO', event: 'LOGIN_SUCCESS',
      userId: user.id, ip,
      message: `Login success: ${user.username}`
    });

    res.json({ message: 'Login successful', token, user: { id: user.id, username: user.username, email: user.email, role: user.role } });
  } catch (err) {
    console.error('[auth] Login error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── GET /api/auth/verify ────────────────────────────────────────────
router.get('/verify', (req, res) => {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.status(401).json({ valid: false });
  try {
    const decoded = verifyToken(token);
    res.json({ valid: true, user: decoded });
  } catch (err) {
    res.status(401).json({ valid: false });
  }
});

// ── GET /api/auth/me ────────────────────────────────────────────
router.get('/me', async (req, res) => {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = verifyToken(token);
    const result = await pool.query('SELECT id, username, email, role, created_at, last_login FROM users WHERE id = $1', [decoded.sub]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ── GET /api/auth/logs — ดู log ของ auth-service (admin only) ─────────
router.get('/logs', async (req, res) => {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const user = verifyToken(token);
    if (user.role !== 'admin') return res.status(403).json({ error: 'admin only' });
    const { limit = 100, offset = 0 } = req.query;
    const result = await pool.query(
      `SELECT * FROM logs ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
      [parseInt(limit), parseInt(offset)]
    );
    const count = await pool.query('SELECT COUNT(*) FROM logs');
    res.json({ logs: result.rows, total: parseInt(count.rows[0].count) });
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

router.get('/health', (req, res) => res.json({ status: 'ok', service: 'auth-service' }));
module.exports = router;