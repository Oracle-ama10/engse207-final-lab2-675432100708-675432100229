const express  = require('express');
const bcrypt   = require('bcryptjs');
const { pool } = require('../db/db');
const { generateToken, verifyToken } = require('../middleware/jwtUtils');

const router = express.Router();

// ฟังก์ชัน Log แบบใหม่ (Set 2) - บันทึกลง auth-db ของตัวเองโดยตรง
async function logEvent({ level, event, userId, message, meta }) {
  try {
    await pool.query(
      `INSERT INTO logs (level, event, user_id, message, meta) 
       VALUES ($1, $2, $3, $4, $5)`,
      [
        level, 
        event, 
        userId || null, 
        message, 
        meta ? JSON.stringify(meta) : null
      ]
    );
  } catch (err) {
    console.error('[AUTH LOG ERROR] Failed to write log:', err.message);
  }
}

// POST /api/auth/register
router.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  // 1. ตรวจสอบข้อมูลเบื้องต้น
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'username, email and password are required' });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    // 2. เช็คว่ามี username หรือ email นี้ในระบบหรือยัง
    const checkUser = await pool.query(
      'SELECT id FROM users WHERE email = $1 OR username = $2', 
      [normalizedEmail, username]
    );

    if (checkUser.rows.length > 0) {
      await logEvent({
        level: 'WARN', event: 'REGISTER_FAILED',
        message: `Register failed: username or email already exists (${normalizedEmail})`,
        meta: { email: normalizedEmail, username }
      });
      return res.status(409).json({ error: 'Email or Username already exists' });
    }

    // 3. เข้ารหัส Password
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // 4. บันทึกข้อมูลลง Database
    const result = await pool.query(
      `INSERT INTO users (username, email, password_hash, role) 
       VALUES ($1, $2, $3, 'member') 
       RETURNING id, username, email, role, created_at`,
      [username, normalizedEmail, passwordHash]
    );

    const newUser = result.rows[0];

    // 5. ส่ง Log ว่าสมัครสำเร็จ
    await logEvent({
      level: 'INFO', event: 'REGISTER_SUCCESS', userId: newUser.id,
      message: `User ${newUser.username} registered successfully`,
      meta: { username: newUser.username, email: newUser.email }
    });

    // 6. ส่ง Response กลับไป (201 Created)
    res.status(201).json({
      message: 'Register สำเร็จ',
      user: newUser
    });

  } catch (err) {
    console.error('[AUTH] Register error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: 'email and password required' });

  const normalizedEmail = email.toLowerCase().trim();

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1', [normalizedEmail]
    );
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      await logEvent({
        level: 'WARN', event: 'LOGIN_FAILED',
        message: `Failed login for ${normalizedEmail}`,
        meta: { email: normalizedEmail }
      });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

    // สร้าง JWT Payload ตามโจทย์ Set 2 (ข้อ 3.4)
    const token = generateToken({
      sub: user.id, email: user.email,
      role: user.role, username: user.username
    });

    await logEvent({
      level: 'INFO', event: 'LOGIN_SUCCESS', userId: user.id,
      message: `User ${user.username} logged in`,
      meta: { username: user.username, role: user.role }
    });

    res.json({
      message: 'Login สำเร็จ', token,
      user: { id: user.id, username: user.username, email: user.email, role: user.role }
    });

  } catch (err) {
    console.error('[AUTH] Login error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/auth/verify
router.get('/verify', (req, res) => {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.status(401).json({ valid: false, error: 'No token' });
  try {
    const decoded = verifyToken(token);
    res.json({ valid: true, user: decoded });
  } catch (err) {
    res.status(401).json({ valid: false, error: err.message });
  }
});

// GET /api/auth/me
router.get('/me', async (req, res) => {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = verifyToken(token);
    const result  = await pool.query(
      'SELECT id, username, email, role, created_at, last_login FROM users WHERE id = $1',
      [decoded.sub]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// GET /api/auth/health
router.get('/health', (_, res) => res.json({ status: 'ok', service: 'auth-service', time: new Date() }));

module.exports = router;