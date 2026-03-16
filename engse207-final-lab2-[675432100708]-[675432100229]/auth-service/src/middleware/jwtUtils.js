const jwt = require('jsonwebtoken');

// ใช้ค่าจาก Environment Variable เป็นหลัก (ถ้าไม่มีจะใช้ dev-shared-secret แทน)
const SECRET  = process.env.JWT_SECRET  || 'dev-shared-secret';
const EXPIRES = process.env.JWT_EXPIRES || '1h';

function generateToken(payload) {
  return jwt.sign(payload, SECRET, { expiresIn: EXPIRES });
}

function verifyToken(token) {
  return jwt.verify(token, SECRET);
}

module.exports = { generateToken, verifyToken };