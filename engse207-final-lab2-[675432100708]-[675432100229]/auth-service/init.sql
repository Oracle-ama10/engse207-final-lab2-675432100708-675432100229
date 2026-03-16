-- ── 1. เตรียมระบบ Cryptography ─────────────────────────────────────
-- เปิดใช้งาน Extension สำหรับเข้ารหัสผ่าน (bcrypt)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── 2. สร้างตาราง Users ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id             SERIAL PRIMARY KEY,
  username       VARCHAR(50) UNIQUE NOT NULL,
  email          VARCHAR(100) UNIQUE NOT NULL,
  password_hash  VARCHAR(255) NOT NULL,
  role           VARCHAR(20) DEFAULT 'member', -- member, admin
  created_at     TIMESTAMP DEFAULT NOW(),
  last_login     TIMESTAMP
);

-- ── 3. สร้างตาราง Logs (ประจำ Auth Service) ────────────────────────
CREATE TABLE IF NOT EXISTS logs (
  id          SERIAL PRIMARY KEY,
  level       VARCHAR(10)  NOT NULL, -- INFO, ERROR, WARN
  event       VARCHAR(100) NOT NULL, -- LOGIN_SUCCESS, LOGIN_FAILED, JWT_INVALID
  user_id     INTEGER,
  message     TEXT,
  meta        JSONB,
  created_at  TIMESTAMP DEFAULT NOW()
);

-- ── 4. Seed Data (ข้อมูลสำหรับทดสอบ) ───────────────────────────────
-- 👤 Admin
INSERT INTO users (username, email, password_hash, role) 
VALUES (
  'admin', 
  'admin@lab.local', 
  crypt('adminpass', gen_salt('bf')), 
  'admin'
) ON CONFLICT (email) DO NOTHING;

-- 👤 Alice (Member)
INSERT INTO users (username, email, password_hash, role) 
VALUES (
  'alice', 
  'alice@lab.local', 
  crypt('alice123', gen_salt('bf')), 
  'member'
) ON CONFLICT (email) DO NOTHING;

-- 👤 Bob (Member)
INSERT INTO users (username, email, password_hash, role) 
VALUES (
  'bob', 
  'bob@lab.local', 
  crypt('bob456', gen_salt('bf')), 
  'member'
) ON CONFLICT (email) DO NOTHING;