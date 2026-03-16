const express = require('express');
const { pool } = require('../db/db');
const { requireAuth } = require('../middleware/authMiddleware');

const router = express.Router();

// Helper: log ลง task-db โดยตรง (ไม่ใช้ log-service แยก)
async function logEvent({ level, event, userId, message, meta }) {
  try {
    await pool.query(
      `INSERT INTO logs (level, event, user_id, message, meta) VALUES ($1,$2,$3,$4,$5)`,
      [level, event, userId || null, message || null, meta ? JSON.stringify(meta) : null]
    );
  } catch (e) {
    console.error('[task-log]', e.message);
  }
}

// 🚨 1. Health Check ต้องอยู่ "ก่อน" requireAuth ไม่งั้น Docker/Railway จะพังเพราะติด 401
router.get('/health', (req, res) => res.json({ status: 'ok', service: 'task-service' }));

// ทุก route ต่อจากนี้จะต้องมี JWT Token เท่านั้น
router.use(requireAuth);

router.get('/', async (req, res) => {
  try {
    let result;
    // 🚨 2. ตัด LEFT JOIN users ทิ้ง เพราะ task-db ไม่มีตาราง users
    if (req.user.role === 'admin') {
      result = await pool.query('SELECT * FROM tasks ORDER BY created_at DESC');
    } else {
      result = await pool.query('SELECT * FROM tasks WHERE user_id = $1 ORDER BY created_at DESC', [req.user.sub]);
    }
    
    // 💡 ทริค: เราเอา username จาก JWT (req.user) ยัดใส่กลับไปให้ Frontend ใช้โชว์ชื่อคนสร้าง Task ได้เลย!
    const tasks = result.rows.map(t => ({
      ...t,
      username: t.user_id === req.user.sub ? req.user.username : `User ID: ${t.user_id}`
    }));

    await logEvent({
      level: 'INFO', event: 'FETCH_TASKS', userId: req.user.sub,
      message: `User ${req.user.sub} fetched tasks`
    });

    res.json({ tasks });
  } catch (err) {
    console.error('[TASK] GET / error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/', async (req, res) => {
  const { title, description, status, priority } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required' });

  try {
    const result = await pool.query(
      'INSERT INTO tasks (user_id, title, description, status, priority) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.sub, title, description || '', status || 'TODO', priority || 'medium']
    );

    await logEvent({
      level: 'INFO', event: 'CREATE_TASK', userId: req.user.sub,
      message: `Task created: ${result.rows[0].id}`, meta: { taskId: result.rows[0].id }
    });

    res.status(201).json({ task: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.put('/:id', async (req, res) => {
  const { id } = req.params;
  const { title, description, status, priority } = req.body;

  try {
    const task = await pool.query('SELECT * FROM tasks WHERE id = $1', [id]);
    if (task.rows.length === 0) return res.status(404).json({ error: 'Task not found' });

    if (req.user.role !== 'admin' && task.rows[0].user_id !== req.user.sub) {
      await logEvent({
        level: 'WARN', event: 'UNAUTHORIZED_EDIT', userId: req.user.sub,
        message: `Attempted to edit task ${id}`
      });
      return res.status(403).json({ error: 'Forbidden' });
    }

    const result = await pool.query(
      'UPDATE tasks SET title = COALESCE($1, title), description = COALESCE($2, description), status = COALESCE($3, status), priority = COALESCE($4, priority), updated_at = NOW() WHERE id = $5 RETURNING *',
      [title, description, status, priority, id]
    );

    await logEvent({
      level: 'INFO', event: 'UPDATE_TASK', userId: req.user.sub,
      message: `Task updated: ${id}`, meta: { taskId: id }
    });

    res.json({ task: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.delete('/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const task = await pool.query('SELECT * FROM tasks WHERE id = $1', [id]);
    if (task.rows.length === 0) return res.status(404).json({ error: 'Task not found' });

    if (req.user.role !== 'admin' && task.rows[0].user_id !== req.user.sub) {
      await logEvent({
        level: 'WARN', event: 'UNAUTHORIZED_DELETE', userId: req.user.sub,
        message: `Attempted to delete task ${id}`
      });
      return res.status(403).json({ error: 'Forbidden' });
    }

    await pool.query('DELETE FROM tasks WHERE id = $1', [id]);

    await logEvent({
      level: 'INFO', event: 'DELETE_TASK', userId: req.user.sub,
      message: `Task deleted: ${id}`, meta: { taskId: id }
    });

    res.json({ message: 'Task deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;