require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const morgan  = require('morgan');
const { pool } = require('./db/db'); 
const userRoutes = require('./routes/users');

const app  = express();
const PORT = process.env.PORT || 3003;

app.use(cors());
app.use(express.json());

// Morgan สำหรับ Log การเรียกใช้งาน API
app.use(morgan('combined', {
  stream: { write: (msg) => console.log(msg.trim()) }
}));

// 🚨 แก้ตรงนี้! ต้องรับ Path /api/users เพื่อให้ตรงกับ Frontend และสคริปต์ตรวจของอาจารย์
app.use('/api/users', userRoutes); 

// 404 Handler
app.use((req, res) => res.status(404).json({ error: 'Route not found' }));

async function start() {
  let retries = 10;
  while (retries > 0) {
    try { 
      // เช็คว่าต่อ DB ติดไหม
      await pool.query('SELECT 1'); 

      // 💡 ไฮไลท์ Set 2: สร้างตารางอัตโนมัติ (Fallback สำหรับ Railway)
      // อิงตาม Schema ในเอกสารอาจารย์เป๊ะๆ
      await pool.query(`
        CREATE TABLE IF NOT EXISTS user_profiles (
          id SERIAL PRIMARY KEY, 
          user_id INTEGER UNIQUE NOT NULL,
          username VARCHAR(50), 
          email VARCHAR(100), 
          role VARCHAR(20) DEFAULT 'member',
          display_name VARCHAR(100), 
          bio TEXT, 
          avatar_url VARCHAR(255),
          updated_at TIMESTAMP DEFAULT NOW()
        );

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
      console.log('[user-service] Database is ready (Tables checked/created)');
      break; 
    }
    catch (err) {
      console.log(`[user-service] Waiting for DB... (${retries} left) - Error: ${err.message}`);
      retries--;
      await new Promise(r => setTimeout(r, 3000));
    }
  }
  app.listen(PORT, () => console.log(`[user-service] Running on port ${PORT}`));
}

start();