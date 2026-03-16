// frontend/config.js
window.APP_CONFIG = {
  // 💻 สำหรับเทสในเครื่อง (Local)
  AUTH_URL: 'http://localhost:3001',
  TASK_URL: 'http://localhost:3002',
  USER_URL: 'http://localhost:3003'

  /* ☁️ เมื่อจะขึ้น Railway ให้สลับมาใช้ด้านล่างนี้:
  AUTH_URL: 'https://auth-service-production-XXXX.up.railway.app',
  TASK_URL: 'https://task-service-production-XXXX.up.railway.app',
  USER_URL: 'https://user-service-production-XXXX.up.railway.app'
  */
};