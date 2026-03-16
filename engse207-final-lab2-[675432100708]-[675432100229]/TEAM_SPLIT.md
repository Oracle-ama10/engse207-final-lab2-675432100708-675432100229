# TEAM_SPLIT.md

## TEAM
- กลุ่มที่: S1-16
- รายวิชา: ENGSE207 Software Architecture

## Team Members
- 67543210070-8 นายธนพล ตรีรัตนานุภาพ

## Work Allocation

### Student 1: นายธนพล ตรีรัตนานุภาพ
งานหลักที่รับผิดชอบได้แก่ การทำงานคนเดียวเพื่อครอบคลุมทุกส่วนของระบบ microservices ดังนี้
1. Auth Service — พัฒนา Login route ด้วยการใช้ bcrypt สำหรับ hash password และ JWT สำหรับ sign/verify token รวมถึงการตรวจสอบสิทธิ์ เพื่อให้ระบบ authentication ปลอดภัยและเชื่อถือได้
2. Nginx — ตั้งค่า HTTPS config ด้วย self-signed certificate, rate limiting เพื่อป้องกันการโจมตี, และ reverse proxy เพื่อ route request อย่างมีประสิทธิภาพและปลอดภัย
3. Database — ออกแบบ schema สำหรับ users, tasks, และ logs รวมถึง seed ข้อมูลผู้ใช้เบื้องต้นใน PostgreSQL เพื่อให้ฐานข้อมูลพร้อมใช้งานตั้งแต่เริ่มต้น
4. Docker Compose — ตั้งค่า services, networks, healthcheck สำหรับตรวจสอบสถานะ container, และ environment variables สำหรับการตั้งค่า เพื่อให้ระบบ container ทำงานได้อย่างราบรื่น
5. Task Service — สร้าง CRUD operations สำหรับ tasks ด้วย JWT middleware และ role-based access สำหรับ admin/member เพื่อจัดการงานอย่างมีสิทธิ์ที่เหมาะสม
6. Log Service — พัฒนาระบบรับ log จาก services อื่นๆ, บันทึกใน DB, และ GET /api/logs พร้อม admin guard เพื่อติดตามและตรวจสอบกิจกรรมในระบบ
7. Frontend — สร้าง index.html สำหรับ Task Board UI และ logs.html สำหรับ Log Dashboard ด้วย JavaScript เพื่อให้ผู้ใช้สามารถ interact กับระบบได้ง่าย
8. ทดสอบระบบ end-to-end อย่างละเอียดและจัดทำ screenshots รวมถึงการตรวจสอบการทำงานของแต่ละ API และ UI เพื่อให้มั่นใจว่าทุกส่วนทำงานได้ถูกต้อง

## Shared Responsibilities(But ME!! Shared With ME!!!)
- ออกแบบ architecture diagram และ flow ของระบบ microservices ด้วยตนเอง รวมถึงการวางแผนการเชื่อมต่อระหว่าง services เพื่อให้โครงสร้างระบบชัดเจนและมีประสิทธิภาพ
- ทดสอบระบบ end-to-end ด้วยตนเองผ่าน Postman โดยส่ง request ไปยังแต่ละ API และตรวจสอบ response รวมถึงการทดสอบ authentication flow เพื่อให้แน่ใจว่าการทำงานถูกต้อง
- จัดทำ README.md และเอกสารประกอบการส่งงานด้วยตนเอง รวมถึงการรวบรวม screenshots และคำอธิบายการใช้งาน เพื่อให้เอกสารครบถ้วนและเข้าใจง่าย
- แก้ปัญหา npm ci ที่เกิดจากไม่มี package-lock.json ด้วยตนเอง โดยรัน npm install เพื่อสร้าง lockfile และซิงค์ dependencies เพื่อให้การ build สำเร็จ
- แก้ไขปัญหา 502 Bad Gateway โดยเพิ่ม dotenv ใน auth-service และซิงค์ package-lock.json เพื่อให้ container รันได้ปกติ และระบบทำงานได้อย่างต่อเนื่อง
- พัฒนาและปรับปรุง UI ใน frontend รวมถึงการจัดการ CSS และ JavaScript เพื่อให้ responsive และใช้งานง่าย เพื่อประสบการณ์ผู้ใช้ที่ดี

## Reason for Work Split
- การแบ่งหน้าที่พิจารณาตามขอบเขตของแต่ละ service เพื่อให้การพัฒนาระบบเป็นไปอย่างมีประสิทธิภาพและชัดเจน โดยทำงานคนเดียวเพื่อครอบคลุมทั้ง security layer ซึ่งรวมถึง Auth Service และการตั้งค่า Nginx สำหรับ HTTPS ซึ่งเป็นโครงสร้างพื้นฐานสำคัญ เพื่อให้ระบบปลอดภัย
- และ business logic layer ซึ่งรวมถึง Task Service, Log Service, และ Frontend ซึ่งเป็นส่วนการทำงานหลักของระบบ เพื่อให้ฟังก์ชันการทำงานครบถ้วน
-การทำงานคนเดียวช่วยให้สามารถควบคุมและปรับปรุงทุกส่วนได้อย่างต่อเนื่องโดยไม่ต้องรอการประสานงาน เพื่อให้พัฒนาได้รวดเร็วและมีคุณภาพ

## Integration Notes
- Auth Service สร้างและออก JWT token หลังจาก login สำเร็จ → Task Service และ Log Service ใช้ JWT เพื่อตรวจสอบสิทธิ์ก่อนให้เข้าถึง resource เช่น การสร้าง task หรือดู logs เพื่อให้การเข้าถึงปลอดภัย
- Nginx ทำหน้าที่เป็น entry point โดยรับ request จาก browser และ route ไปยัง services ต่างๆ ภายใน Docker network รวมถึงการ terminate HTTPS เพื่อให้การสื่อสารเข้ารหัส
- Log Service รับ log events จาก Auth Service และ Task Service ผ่าน POST /api/logs/internal เพื่อบันทึกกิจกรรมต่างๆ ในระบบ เพื่อให้ติดตามและวิเคราะห์ได้
- Frontend ส่ง request ไปยัง API ทุกตัวผ่าน HTTPS ที่ Nginx ตั้งค่าไว้ รวมถึงการแสดงผลข้อมูลจาก Task Service และ Log Service เพื่อให้ผู้ใช้เห็นข้อมูลแบบ real-time
