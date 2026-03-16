-- ── 1. สร้างตารางเก็บโปรไฟล์ผู้ใช้ ──────────────────────────────────
-- ตารางนี้เก็บข้อมูลส่วนตัวที่ดึงมาโชว์ในหน้า Dashboard และ Profile
CREATE TABLE IF NOT EXISTS user_profiles (
  id           SERIAL PRIMARY KEY,
  user_id      INTEGER UNIQUE NOT NULL, -- เชื่อมกับ ID จาก Auth DB
  username     VARCHAR(50),
  email        VARCHAR(100),
  role         VARCHAR(20) DEFAULT 'member',
  display_name VARCHAR(100),
  bio          TEXT,
  avatar_url   VARCHAR(255),
  updated_at   TIMESTAMP DEFAULT NOW()
);

-- ── 2. สร้างตาราง Logs (ประจำ User Service) ────────────────────────
-- จำเป็นต้องมีแยกตามโจทย์การทำ Database Per Service
CREATE TABLE IF NOT EXISTS logs (
  id          SERIAL PRIMARY KEY,
  level       VARCHAR(10)  NOT NULL, -- INFO, ERROR
  event       VARCHAR(100) NOT NULL, -- PROFILE_UPDATED, PROFILE_VIEWED
  user_id     INTEGER,
  message     TEXT,
  meta        JSONB,
  created_at  TIMESTAMP DEFAULT NOW()
);

-- ── 3. Seed Data (ข้อมูลโปรไฟล์เริ่มต้น) ──────────────────────────────
-- 👤 Admin Profile (user_id = 1)
INSERT INTO user_profiles (user_id, username, email, role, display_name, bio) 
VALUES (1, 'admin', 'admin@lab.local', 'admin', 'System Administrator', 'ดูแลระบบภาพรวม')
ON CONFLICT (user_id) DO NOTHING;

-- 👤 Alice Profile (user_id = 2)
INSERT INTO user_profiles (user_id, username, email, role, display_name, bio) 
VALUES (2, 'alice', 'alice@lab.local', 'member', 'Alice Wonderland', 'ชอบเขียนโปรแกรมและดีไซน์')
ON CONFLICT (user_id) DO NOTHING;

-- 👤 Bob Profile (user_id = 3)
INSERT INTO user_profiles (user_id, username, email, role, display_name, bio) 
VALUES (3, 'bob', 'bob@lab.local', 'member', 'Bob Builder', 'ถนัดงานโครงสร้างและ Backend')
ON CONFLICT (user_id) DO NOTHING;