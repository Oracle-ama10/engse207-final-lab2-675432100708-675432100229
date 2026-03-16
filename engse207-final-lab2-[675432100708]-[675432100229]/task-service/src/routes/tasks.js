const express     = require('express');
const { pool }    = require('../db/db');
const requireAuth = require('../middleware/authMiddleware');

const router = express.Router();

// 📝 ระบบ Log ประจำ task-db (บันทึกลงฐานข้อมูลตัวเอง)
async function logEvent({ level, event, userId, message, meta }) {
  try {
    await pool.query(
      `INSERT INTO logs (level, event, user_id, message, meta) VALUES ($1, $2, $3, $4, $5)`,
      [level, event, userId || null, message, meta ? JSON.stringify(meta) : null]
    );
  } catch (err) {
    console.error('[TASK LOG ERROR] Failed to write log:', err.message);
  }
}

router.get('/health', (_, res) => res.json({ status: 'ok', service: 'task-service' }));

router.use(requireAuth);

// GET /api/tasks/
router.get('/', async (req, res) => {
  try {
    let result;
    // ⚠️ ตัดการ JOIN users ออก เพราะอยู่คนละ Database
    if (req.user.role === 'admin') {
      result = await pool.query(
        'SELECT * FROM tasks ORDER BY created_at DESC'
      );
    } else {
      result = await pool.query(
        'SELECT * FROM tasks WHERE user_id = $1 ORDER BY created_at DESC',
        [req.user.sub]
      );
    }
    res.json({ tasks: result.rows, count: result.rowCount });
  } catch (err) {
    console.error('[TASK] Fetch error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/tasks/
router.post('/', async (req, res) => {
  const { title, description, status = 'TODO', priority = 'medium' } = req.body;
  if (!title) return res.status(400).json({ error: 'title is required' });
  try {
    const result = await pool.query(
      'INSERT INTO tasks (user_id, title, description, status, priority) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [req.user.sub, title, description, status, priority]
    );
    const task = result.rows[0];
    
    await logEvent({
      level: 'INFO', event: 'TASK_CREATED', userId: req.user.sub,
      message: `Task created: "${title}"`, 
      meta: { task_id: task.id, title }
    });
    
    res.status(201).json({ task });
  } catch (err) {
    console.error('[TASK] Create error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/tasks/:id
router.put('/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const check = await pool.query('SELECT * FROM tasks WHERE id = $1', [id]);
    if (!check.rows[0]) return res.status(404).json({ error: 'Task not found' });
    
    // ตรวจสอบสิทธิ์ (เจ้าของงาน หรือ Admin เท่านั้น)
    if (check.rows[0].user_id !== req.user.sub && req.user.role !== 'admin')
      return res.status(403).json({ error: 'Forbidden' });

    const { title, description, status, priority } = req.body;
    const result = await pool.query(
      `UPDATE tasks SET
        title=COALESCE($1,title), description=COALESCE($2,description),
        status=COALESCE($3,status), priority=COALESCE($4,priority), updated_at=NOW()
       WHERE id=$5 RETURNING *`,
      [title, description, status, priority, id]
    );

    await logEvent({
      level: 'INFO', event: 'TASK_UPDATED', userId: req.user.sub,
      message: `Task ${id} updated`,
      meta: { task_id: id }
    });

    res.json({ task: result.rows[0] });
  } catch (err) {
    console.error('[TASK] Update error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/tasks/:id
router.delete('/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const check = await pool.query('SELECT * FROM tasks WHERE id = $1', [id]);
    if (!check.rows[0]) return res.status(404).json({ error: 'Task not found' });
    
    if (check.rows[0].user_id !== req.user.sub && req.user.role !== 'admin')
      return res.status(403).json({ error: 'Forbidden' });

    await pool.query('DELETE FROM tasks WHERE id = $1', [id]);
    
    await logEvent({
      level: 'INFO', event: 'TASK_DELETED', userId: req.user.sub,
      message: `Task ${id} deleted`
    });
    
    res.json({ message: 'Task deleted' });
  } catch (err) {
    console.error('[TASK] Delete error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;