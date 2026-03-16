const { Pool } = require('pg');

// ใช้ DATABASE_URL เพื่อให้รองรับทั้ง Local (Docker) และ Railway Cloud
const pool = new Pool({ 
  connectionString: process.env.DATABASE_URL 
});

module.exports = { pool };