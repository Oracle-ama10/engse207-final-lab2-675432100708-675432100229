require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const morgan  = require('morgan');
// 💡 แก้ไข: ดึงมาแค่ pool พอ ไม่ต้องใช้ initDB
const { pool } = require('./db/db'); 
const userRoutes = require('./routes/users');

const app  = express();
const PORT = process.env.PORT || 3003;

app.use(cors());
app.use(express.json());
app.use(morgan('combined', {
  stream: { write: (msg) => console.log(msg.trim()) }
}));

// 💡 แก้ไข: รับที่รากเลย เพราะ Nginx หั่น /api/users ออกให้แล้ว
app.use('/', userRoutes); 
app.use((req, res) => res.status(404).json({ error: 'Route not found' }));

async function start() {
  let retries = 10;
  while (retries > 0) {
    try { 
      // 💡 แก้ไข: ใช้แค่ SELECT 1 เช็คว่า DB พร้อมไหม (เหมือน auth/task)
      await pool.query('SELECT 1'); 
      break; 
    }
    catch (err) {
      console.log(`[user-service] Waiting for DB... (${retries} retries left)`);
      retries--;
      await new Promise(r => setTimeout(r, 3000));
    }
  }
  app.listen(PORT, () => console.log(`[user-service] Running on port ${PORT}`));
}

start();