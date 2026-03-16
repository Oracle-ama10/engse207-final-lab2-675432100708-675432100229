# ENGSE207 Software Architecture  
## README — Final Lab Set 1: Microservices + HTTPS + Lightweight Logging

> เอกสารฉบับนี้ใช้เป็น `README.md` สำหรับ repository ของ **Final Lab Set 1**  
> นักศึกษาสามารถปรับแก้รายละเอียด เช่น ชื่อสมาชิก, ภาพ architecture, URL หรือคำอธิบายเพิ่มเติม ให้สอดคล้องกับงานจริงของกลุ่ม

---

## 1. ข้อมูลรายวิชาและสมาชิก

**รายวิชา:** ENGSE207 Software Architecture  
**ชื่องาน:** Final Lab — ชุดที่ 1: Microservices + HTTPS + Lightweight Logging  

**สมาชิกในกลุ่ม**
- ชื่อ-สกุล / รหัสนักศึกษา: นายธนพล ตรีรัตนานุถาพ / 67543210070-8

**Repository:** `Final-lab-set1/`

---

## 2. ภาพรวมของระบบ

Final Lab ชุดที่ 1 เป็นการพัฒนาระบบ Task Board แบบ Microservices โดยเน้นหัวข้อสำคัญดังนี้

- การทำงานแบบแยก service
- การใช้ Nginx เป็น API Gateway
- การเปิดใช้งาน HTTPS ด้วย Self-Signed Certificate
- การยืนยันตัวตนด้วย JWT
- การจัดเก็บ log แบบ Lightweight Logging ผ่าน Log Service
- การเชื่อมต่อ Frontend กับ Backend ผ่าน HTTPS

งานชุดนี้ **ไม่มี Register** และใช้เฉพาะ **Seed Users** ที่กำหนดไว้ในฐานข้อมูล

---

## 3. วัตถุประสงค์ของงาน

งานนี้มีจุดมุ่งหมายเพื่อฝึกให้นักศึกษาสามารถ

- ออกแบบระบบแบบ Microservices ในระดับพื้นฐาน
- ใช้ Nginx เป็น reverse proxy และ TLS termination
- ใช้ JWT สำหรับ authentication ระหว่าง frontend และ backend
- ออกแบบ logging flow ผ่าน REST API และจัดเก็บ log ลงฐานข้อมูล
- ใช้ Docker Compose เพื่อรวมทุก service ให้ทำงานร่วมกันได้

---

## 4. Architecture Overview

> ให้วางภาพ architecture diagram ของกลุ่มไว้ในส่วนนี้  
> เช่น `docs/architecture-set1.png` หรือแทรกรูปจากโฟลเดอร์ `screenshots/`

```text
Browser / Postman
       │
       │ HTTPS :443
       ▼
Nginx (API Gateway)
   ├── /api/auth/*  → auth-service
   ├── /api/tasks/* → task-service
   ├── /api/logs/*  → log-service
   └── /            → frontend
            │
            ▼
     PostgreSQL (shared DB)
```

### Services ที่ใช้ในระบบ
- **nginx** — API Gateway, HTTPS, rate limiting
- **frontend** — หน้าเว็บ Task Board และ Log Dashboard
- **auth-service** — Login, Verify, Me
- **task-service** — CRUD Tasks
- **log-service** — รับและแสดง logs
- **postgres** — shared database

---

## 5. โครงสร้าง Repository

```text
final-lab-set1/
├── README.md
├── TEAM_SPLIT.md
├── INDIVIDUAL_REPORT_[studentid].md
├── docker-compose.yml
├── .env.example
├── nginx/
├── frontend/
├── auth-service/
├── task-service/
├── log-service/
├── db/
├── scripts/
└── screenshots/
```

---

## 6. เทคโนโลยีที่ใช้

- Node.js / Express.js
- PostgreSQL
- Nginx
- Docker / Docker Compose
- HTML / CSS / JavaScript
- JWT
- bcryptjs

---

## 7. การตั้งค่าและการรันระบบ

### 7.1 สร้าง Self-Signed Certificate

```bash
chmod +x scripts/gen-certs.sh
./scripts/gen-certs.sh
```

### 7.2 สร้างไฟล์ `.env`
คัดลอกจาก `.env.example` แล้วกำหนดค่าตามต้องการ เช่น

```env
POSTGRES_DB=taskboard
POSTGRES_USER=admin
POSTGRES_PASSWORD=secret123
JWT_SECRET=engse207-super-secret-change-me
JWT_EXPIRES=1h
```

### 7.3 สร้าง bcrypt hash สำหรับ Seed Users
ในงานชุดนี้ กลุ่มของเรากำหนดให้ **สร้าง bcrypt hash เอง** ก่อนรันระบบ

ตัวอย่างคำสั่ง:

```bash
node -e "const b=require('bcryptjs'); console.log(b.hashSync('alice123',10))"
node -e "const b=require('bcryptjs'); console.log(b.hashSync('bob456',10))"
node -e "const b=require('bcryptjs'); console.log(b.hashSync('adminpass',10))"
```

จากนั้นนำค่าที่ได้ไปแทนในไฟล์ `db/init.sql`

### 7.4 รันระบบ

```bash
docker compose down -v
docker compose up --build
```

### 7.5 เปิดใช้งานผ่าน Browser
- Frontend: `https://localhost`
- Log Dashboard: `https://localhost/logs.html`

> หมายเหตุ: เนื่องจากใช้ self-signed certificate browser อาจขึ้นคำเตือนด้านความปลอดภัย ให้กดยอมรับเพื่อเข้าทดสอบ

---

## 8. Seed Users สำหรับทดสอบ

| Username | Email | Password | Role |
|---|---|---|---|
| alice | alice@lab.local | alice123 | member |
| bob | bob@lab.local | bob456 | member |
| admin | admin@lab.local | adminpass | admin |

> หมายเหตุ: ต้อง generate bcrypt hash จริงแล้วแทนค่าลงใน `db/init.sql` ก่อน login

---

## 9. API Summary

### Auth Service
- `POST /api/auth/login`
- `GET /api/auth/verify`
- `GET /api/auth/me`
- `GET /api/auth/health`

### Task Service
- `GET /api/tasks/health`
- `GET /api/tasks/`
- `POST /api/tasks/`
- `PUT /api/tasks/:id`
- `DELETE /api/tasks/:id`

### Log Service
- `POST /api/logs/internal`
- `GET /api/logs/`
- `GET /api/logs/stats`
- `GET /api/logs/health`

---

## 10. การทดสอบระบบ

### ตัวอย่างลำดับการทดสอบ
1. รัน `docker compose up --build`
2. เปิด `https://localhost`
3. Login ด้วย seed users
4. สร้าง task ใหม่
5. ดูรายการ task
6. แก้ไข task
7. ลบ task
8. ทดสอบกรณีไม่มี JWT → ต้องได้ `401`
9. ทดสอบ Log Dashboard
10. ทดสอบ rate limiting ของ login

### ตัวอย่าง curl
```bash
BASE="https://localhost"

TOKEN=$(curl -sk -X POST $BASE/api/auth/login   -H "Content-Type: application/json"   -d '{"email":"alice@lab.local","password":"alice123"}' |   python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

curl -sk $BASE/api/tasks/ -H "Authorization: Bearer $TOKEN"
```

---

## 11. Screenshots

โฟลเดอร์ `screenshots/` ของกลุ่มนี้ประกอบด้วยภาพดังต่อไปนี้

- `01_docker_running.png`
![01](screenshots/01_docker_running.png)
- `02_https_browser.png`
![02](screenshots/02_https_browser.png)
- `03_login_success_alice.png`
![03](screenshots/03_Login_Success_(alice).png)
- `03_login_success_admin.png`
![03](screenshots/03_Login_Success_(admin).png)
- `04_login_fail.png`
![04](screenshots/04_login_fail.png)
- `05_create_task.png`
![05](screenshots/05_create_task.png)
- `06_get_tasks.png`
![06](screenshots/06_get_tasks.png)
- `07_update_task.png`
![07](screenshots/07_update_task.png)
- `08_delete_task.png`
![08](screenshots/08_delete_task.png)
- `09_no_jwt_401.png`
![09](screenshots/09_no_jwt_401.png)
- `10_logs_api.png`
![10](screenshots/10_logs_api_200.png)
- `11_rate_limit.png`
![11](screenshots/11_rate_limit.png) 
- `12_frontend_screenshot.png`
![12](screenshots/12_frontend_screenshot.png)

---

## 12. การแบ่งงานของทีม

รายละเอียดการแบ่งงานของสมาชิกอยู่ในไฟล์:

- `TEAM_SPLIT.md`

และรายงานรายบุคคลของสมาชิกแต่ละคนอยู่ในไฟล์:

- `INDIVIDUAL_REPORT_[studentid].md`

---

## 13. ปัญหาที่พบและแนวทางแก้ไข

- พบปัญหา 502 Bad Gateway จาก Nginx เพราะ auth-service ไม่สามารถรันได้เนื่องจากขาด module dotenv
  วิธีแก้ไขคือเพิ่ม dotenv ใน package.json ของ auth-service และรัน npm install เพื่อซิงค์ package-lock.json

- พบปัญหาในขั้นตอน npm ci ไม่สามารถทำงานได้เนื่องจากไม่มีไฟล์ package-lock.json ใน auth-service
  วิธีแก้ไขคือรันคำสั่ง npm install ภายในโฟลเดอร์ auth-service เพื่อสร้าง lockfile ก่อน build

- ขณะเปิดใช้งานระบบผ่าน browser มีการแจ้งเตือนเกี่ยวกับ self-signed certificate
  วิธีแก้ไขคือเลือก Advanced → Proceed to localhost เพื่อยอมรับ certificate ชั่วคราวสำหรับการทดสอบ

---

## 14. ข้อจำกัดของระบบ

- ระบบใช้ self-signed certificate ซึ่งไม่ปลอดภัยสำหรับ production และต้องมีการตั้งค่า certificate จริง
- ใช้ shared database เพียงหนึ่งก้อน ทำให้ไม่สามารถ scale แยก service ได้
- ไม่มีระบบ register สำหรับผู้ใช้ใหม่ จำกัดเฉพาะ seed users
- logging เป็นแบบ lightweight ไม่มี centralized logging หรือ monitoring เต็มรูปแบบ
- UI ของ frontend ยังไม่ responsive เต็มที่และอาจมีปัญหาในอุปกรณ์ต่างๆ
- ไม่มีระบบ caching หรือ optimization สำหรับ performance

---

## 15. การต่อยอดไปยัง Set 2

ใน Set 2 จะพัฒนาระบบให้ซับซ้อนขึ้นโดย:

- เพิ่ม Register API และ User Service เพื่อจัดการผู้ใช้แบบครบถ้วน
- เปลี่ยนจาก shared database เป็น database-per-service เพื่อเพิ่มความยืดหยุ่น
- Deploy ระบบบน Railway Cloud แทนการรันในเครื่อง
- ออกแบบ gateway strategy ที่ซับซ้อนขึ้นสำหรับการจัดการหลาย services
- เพิ่มระบบ notification และ advanced logging
- ปรับปรุง UI/UX ให้ responsive และเพิ่มฟีเจอร์ใหม่

---

## 16. ภาคผนวก

### ไฟล์สำคัญใน repository
- `docker-compose.yml`
- `nginx/nginx.conf`
- `db/init.sql`
- `auth-service/src/routes/auth.js`
- `task-service/src/routes/tasks.js`
- `log-service/src/index.js`
- `frontend/index.html`
- `frontend/logs.html`

---

> เอกสารฉบับนี้เป็น README สำหรับงาน Final Lab Set 1 ของกลุ่ม และจัดทำเพื่อประกอบการส่งงานในรายวิชา ENGSE207 Software Architecture