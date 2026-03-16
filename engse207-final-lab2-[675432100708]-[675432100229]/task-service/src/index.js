require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const { pool } = require('./db/db');
const taskRoutes = require('./routes/tasks');

const app  = express();
const PORT = process.env.PORT || 3002;

app.use(cors());
app.use(express.json());

// 💡 แก้ไขตรงนี้: รับที่รากเลย เพราะ Nginx จัดการตัด /api/tasks/ ออกมาให้แล้ว
app.use('/', taskRoutes); 

async function start() {
  let retries = 10;
  while (retries > 0) {
    try { await pool.query('SELECT 1'); break; }
    catch (e) {
      console.log(`[task-service] Waiting for DB... (${retries} left)`);
      retries--;
      await new Promise(r => setTimeout(r, 3000));
    }
  }
  app.listen(PORT, () => console.log(`[task-service] Running on :${PORT}`));
}
start();