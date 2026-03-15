const express = require('express');
const bcrypt = require('bcryptjs');
const pool = require('../db/db');
const { generateToken, verifyToken } = require('../middleware/jwtUtils');

const router = express.Router();

// Register
router.post('/register', async (req, res) => {
  const { email, password, name, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, name, role) VALUES ($1, $2, $3, $4) RETURNING user_id, email, name, role',
      [email, hashedPassword, name, role || 'member']
    );
    const user = result.rows[0];
    const token = generateToken({ sub: user.user_id, email: user.email, role: user.role, username: user.name });
    res.json({ user, token });
  } catch (err) {
    res.status(400).json({ error: 'User already exists or invalid data' });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = generateToken({ sub: user.user_id, email: user.email, role: user.role, username: user.name });
    res.json({ user: { user_id: user.user_id, email: user.email, name: user.name, role: user.role }, token });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify token
router.post('/verify', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = authHeader.slice(7);
  try {
    const decoded = verifyToken(token);
    const result = await pool.query('SELECT user_id, email, name, role FROM users WHERE user_id = $1', [decoded.sub]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'User not found' });
    }
    res.json({ valid: true, user: result.rows[0] });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Get current user
router.get('/me', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = authHeader.slice(7);
  try {
    const decoded = verifyToken(token);
    const result = await pool.query('SELECT user_id, email, name, role, created_at FROM users WHERE user_id = $1', [decoded.sub]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'User not found' });
    }
    const user = result.rows[0];
    res.json({ user: { user_id: user.user_id, email: user.email, name: user.name, role: user.role, created_at: user.created_at } });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

module.exports = router;