-- ── 1. สร้างตารางเก็บงาน (Tasks) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS tasks (
  id           SERIAL PRIMARY KEY,
  user_id      INTEGER NOT NULL, -- ลิงก์กับ ID จาก Auth DB (1=Admin, 2=Alice, 3=Bob)
  title        VARCHAR(200) NOT NULL,
  description  TEXT,
  status       VARCHAR(20) DEFAULT 'TODO', -- TODO, IN_PROGRESS, DONE
  priority     VARCHAR(10) DEFAULT 'medium', -- low, medium, high
  created_at   TIMESTAMP DEFAULT NOW(),
  updated_at   TIMESTAMP DEFAULT NOW()
);

-- ── 2. สร้างตาราง Logs (ประจำ Task Service) ────────────────────────
CREATE TABLE IF NOT EXISTS logs (
  id          SERIAL PRIMARY KEY,
  level       VARCHAR(10)  NOT NULL, -- INFO, ERROR
  event       VARCHAR(100) NOT NULL, -- TASK_CREATED, TASK_UPDATED, TASK_DELETED
  user_id     INTEGER,
  message     TEXT,
  meta        JSONB,
  created_at  TIMESTAMP DEFAULT NOW()
);

-- ── 3. Seed Data (งานเริ่มต้นสำหรับทดสอบ) ──────────────────────────────
-- 📝 งานของ Admin (user_id = 1)
INSERT INTO tasks (user_id, title, description, status, priority) 
VALUES (1, 'ตรวจสอบความปลอดภัยระบบ', 'เช็กช่องโหว่ Nginx และ JWT', 'IN_PROGRESS', 'high');

-- 📝 งานของ Alice (user_id = 2)
INSERT INTO tasks (user_id, title, description, status, priority) 
VALUES (2, 'ออกแบบ UI หน้า Profile', 'ทำหน้าจอให้รองรับการแก้ไขชื่อเล่น', 'DONE', 'medium');

-- 📝 งานของ Bob (user_id = 3)
INSERT INTO tasks (user_id, title, description, status, priority) 
VALUES (3, 'Setup Database Per Service', 'แยก DB ออกเป็น 3 ก้อนตามโจทย์', 'TODO', 'high');