require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const { pool } = require('./db/db');
const authRoutes = require('./routes/auth');

const app  = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

app.use('/api/auth', authRoutes);

async function start() {
  let retries = 10;
  while (retries > 0) {
    try { 
      await pool.query('SELECT 1'); 
      await pool.query(`
        -- 1. สร้างตาราง users (เพิ่ม last_login เผื่อสร้างใหม่)
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          username VARCHAR(50) UNIQUE NOT NULL,
          password_hash VARCHAR(255) NOT NULL, 
          email VARCHAR(100) UNIQUE NOT NULL,
          role VARCHAR(20) DEFAULT 'member',
          last_login TIMESTAMP,
          created_at TIMESTAMP DEFAULT NOW()
        );

        -- 2. ท่าไม้ตาย! เติมคอลัมน์ last_login ลงไปในตารางเก่าที่สร้างไปแล้ว (กัน Error)
        ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP;

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
      console.log('[auth-service] Database is ready (Tables checked/created)');
      break; 
    }
    catch (e) {
      console.log(`[auth-service] Waiting for DB... (${retries} left)`);
      retries--;
      await new Promise(r => setTimeout(r, 3000));
    }
  }
  app.listen(PORT, () => console.log(`[auth-service] Running on :${PORT}`));
}
start();