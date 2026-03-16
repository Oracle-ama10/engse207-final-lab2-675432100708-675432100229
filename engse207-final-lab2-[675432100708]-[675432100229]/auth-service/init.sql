-- เปิดใช้งาน Extension สำหรับเข้ารหัสผ่าน (bcrypt) ใน PostgreSQL
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1. สร้างตาราง users
CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  username      VARCHAR(50) UNIQUE NOT NULL,
  email         VARCHAR(100) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role          VARCHAR(20) DEFAULT 'member',
  created_at    TIMESTAMP DEFAULT NOW(),
  last_login    TIMESTAMP
);

-- 2. สร้างตาราง logs ประจำ auth-db
CREATE TABLE IF NOT EXISTS logs (
  id         SERIAL PRIMARY KEY,
  level      VARCHAR(10)  NOT NULL,
  event      VARCHAR(100) NOT NULL,
  user_id    INTEGER,
  message    TEXT,
  meta       JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

-- 3. สร้างข้อมูลแอดมินเริ่มต้น (Seed Data) ไว้ใช้ทดสอบ Test Case 10
-- รหัสผ่านคือ: adminpass
INSERT INTO users (username, email, password_hash, role) 
VALUES (
  'admin', 
  'admin@lab.local', 
  crypt('adminpass', gen_salt('bf')), 
  'admin'
) ON CONFLICT (email) DO NOTHING;