const jwt = require('jsonwebtoken');

const verifyToken = (token) => {
  try {
    // ใช้ JWT_SECRET จากไฟล์ .env ในการถอดรหัส
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    throw new Error('Invalid or expired token');
  }
};

module.exports = { verifyToken };