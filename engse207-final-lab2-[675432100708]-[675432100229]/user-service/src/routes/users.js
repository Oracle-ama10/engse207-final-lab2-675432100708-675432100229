const express = require('express');
const { pool } = require('../db/db');
const { requireAuth, requireRole } = require('../middleware/authMiddleware');

const router = express.Router();

// 📝 ระบบ Log ประจำ user-service (ลง DB ตัวเองตาม Set 2)
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

// 🟢 GET /api/users/health (ย้ายมาไว้บนสุด เพื่อให้ Cloud เช็คสถานะได้ง่าย)
router.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'user-service' });
});

// ── ทุก Route ต่อจากนี้ต้องใช้ JWT Token ──
router.use(requireAuth);

// 👤 GET /api/users/me — ดูโปรไฟล์ตัวเอง (และสร้างอัตโนมัติถ้ายังไม่มี)
router.get('/me', async (req, res) => {
  const { sub, username, email, role } = req.user;

  try {
    let result = await pool.query(
      'SELECT * FROM user_profiles WHERE user_id = $1',
      [sub]
    );

    // 💡 ถ้าเป็นผู้ใช้ใหม่ ยังไม่มีข้อมูลใน user-db ให้สร้าง Profile เริ่มต้นทันที
    if (result.rows.length === 0) {
      result = await pool.query(
        `INSERT INTO user_profiles (user_id, username, email, role, display_name) 
         VALUES ($1, $2, $3, $4, $5) RETURNING *`,
        [sub, username, email, role, username] // ใช้ username เป็นชื่อแสดงแทนไปก่อน
      );
      
      await logEvent({ 
        level: 'INFO', event: 'PROFILE_AUTO_CREATED', userId: sub, 
        message: `Auto-created profile for user: ${username}` 
      });
    }

    // 🚨 สำคัญ: ส่งกลับในชื่อ "profile" เพื่อให้ตรงกับหน้าเว็บ Frontend
    res.json({ profile: result.rows[0] });
  } catch (err) {
    console.error('[USER] /me error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ✏️ PUT /api/users/me — แก้ไขโปรไฟล์ตัวเอง
router.put('/me', async (req, res) => {
  const { sub } = req.user;
  const { display_name, bio, avatar_url } = req.body;

  try {
    const result = await pool.query(
      `UPDATE user_profiles 
       SET display_name = COALESCE($1, display_name), 
           bio = COALESCE($2, bio), 
           avatar_url = COALESCE($3, avatar_url), 
           updated_at = NOW() 
       WHERE user_id = $4 RETURNING *`,
      [display_name, bio, avatar_url, sub]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'ไม่พบข้อมูล profile' });
    }
    
    await logEvent({ 
      level: 'INFO', event: 'PROFILE_UPDATED', userId: sub, 
      message: `User ${sub} updated their profile` 
    });

    // 🚨 ส่งกลับในชื่อ "profile" เช่นกัน
    res.json({ message: 'อัปเดตโปรไฟล์สำเร็จ', profile: result.rows[0] });
  } catch (err) {
    console.error('[USER] Update profile error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// 👑 GET /api/users — ดูรายชื่อผู้ใช้ทั้งหมด (Admin Only)
router.get('/', requireRole('admin'), async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, user_id, username, display_name, email, role, updated_at FROM user_profiles ORDER BY user_id ASC'
    );
    res.json({ users: result.rows, count: result.rowCount });
  } catch (err) {
    console.error('[USER] List error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;