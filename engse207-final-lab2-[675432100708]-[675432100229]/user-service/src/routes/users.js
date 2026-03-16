const express = require('express');
const { pool } = require('../db/db');
const { requireAuth, requireRole } = require('../middleware/authMiddleware');

const router = express.Router();

// 📝 ระบบ Log ประจำ user-service (บังคับตาม Set 2)
async function logEvent({ level, event, userId, message, meta }) {
  try {
    await pool.query(
      `INSERT INTO logs (level, event, user_id, message, meta) VALUES ($1, $2, $3, $4, $5)`,
      [level, event, userId || null, message, meta ? JSON.stringify(meta) : null]
    );
  } catch (err) {
    console.error('[USER LOG ERROR] Failed to write log:', err.message);
  }
}

// GET /api/users/me — ดูโปรไฟล์ตัวเอง (และสร้างอัตโนมัติถ้ายังไม่มี)
router.get('/me', requireAuth, async (req, res) => {
  // ข้อมูลเหล่านี้ได้มาจาก JWT Payload ที่แกะไว้ใน middleware (req.user)
  const { sub, username, email, role } = req.user;

  try {
    let result = await pool.query(
      'SELECT * FROM user_profiles WHERE user_id = $1',
      [sub]
    );

    // 💡 ไฮไลท์ Set 2: ถ้าเพิ่งสมัครใหม่ยังไม่มีโปรไฟล์ ให้สร้างอัตโนมัติ
    if (result.rows.length === 0) {
      result = await pool.query(
        `INSERT INTO user_profiles (user_id, username, email, role) 
         VALUES ($1, $2, $3, $4) RETURNING *`,
        [sub, username, email, role]
      );
      
      await logEvent({ 
        level: 'INFO', event: 'PROFILE_AUTO_CREATED', userId: sub, 
        message: `Auto-created profile for user_id ${sub}` 
      });
    }

    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error('[USER] /me error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/users/me — แก้ไขโปรไฟล์ตัวเอง (เพื่อนลืมทำอันนี้)
router.put('/me', requireAuth, async (req, res) => {
  const { sub } = req.user;
  const { display_name, bio, avatar_url } = req.body;

  try {
    const result = await pool.query(
      `UPDATE user_profiles 
       SET display_name = $1, bio = $2, avatar_url = $3, updated_at = NOW() 
       WHERE user_id = $4 RETURNING *`,
      [display_name, bio, avatar_url, sub]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'ไม่พบข้อมูล profile' });
    }
    
    await logEvent({ 
      level: 'INFO', event: 'PROFILE_UPDATED', userId: sub, 
      message: `User_id ${sub} updated their profile` 
    });

    res.json({ message: 'อัปเดตโปรไฟล์สำเร็จ', user: result.rows[0] });
  } catch (err) {
    console.error('[USER] Update profile error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/users — ดู users ทั้งหมด (admin only)
router.get('/', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    // แก้คอลัมน์ name เป็น username และ display_name ให้ตรงกับ Schema จริง
    const result = await pool.query(
      'SELECT id, user_id, username, display_name, email, role, updated_at FROM user_profiles ORDER BY id ASC'
    );
    res.json({ users: result.rows, total: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/users/health
router.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'user-service' });
});

module.exports = router;