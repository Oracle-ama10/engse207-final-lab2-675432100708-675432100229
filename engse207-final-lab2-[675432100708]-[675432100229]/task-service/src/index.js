require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const { pool } = require('./db/db');
const taskRoutes = require('./routes/tasks');

const app  = express();
const PORT = process.env.PORT || 3002;

app.use(cors());
app.use(express.json());

app.use('/api/tasks', taskRoutes); 

async function start() {
  let retries = 10;
  while (retries > 0) {
    try { 
      await pool.query('SELECT 1');
      await pool.query(`
        -- 1. สร้างตาราง tasks ใหม่ (ใส่ priority เผื่อไว้)
        CREATE TABLE IF NOT EXISTS tasks (
          id SERIAL PRIMARY KEY,
          title VARCHAR(100) NOT NULL,
          description TEXT,
          status VARCHAR(20) DEFAULT 'pending',
          priority VARCHAR(20) DEFAULT 'medium', 
          user_id INTEGER NOT NULL,
          created_at TIMESTAMP DEFAULT NOW(),
          updated_at TIMESTAMP DEFAULT NOW()
        );

        -- 2. ท่าไม้ตาย! เติมคอลัมน์ priority ลงไปในตารางเก่าที่สร้างไปแล้ว
        ALTER TABLE tasks ADD COLUMN IF NOT EXISTS priority VARCHAR(20) DEFAULT 'medium';

        -- 3. สร้างตาราง logs
        CREATE TABLE IF NOT EXISTS logs (
          id SERIAL PRIMARY KEY,
          level VARCHAR(10) NOT NULL,
          event VARCHAR(100) NOT NULL,
          user_id INTEGER,
          message TEXT,
          meta JSONB,
          created_at TIMESTAMP DEFAULT NOW()
        );
      `);
      console.log('[task-service] Database is ready (Tables checked/created)');
      break; 
    }
    catch (e) {
      console.log(`[task-service] Waiting for DB... (${retries} left)`);
      retries--;
      await new Promise(r => setTimeout(r, 3000));
    }
  }
  app.listen(PORT, () => console.log(`[task-service] Running on :${PORT}`));
}
start();