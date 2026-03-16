const { verifyToken } = require('./jwtUtils');

// 1. ฟังก์ชันตรวจ Token ทั่วไป
const requireAuth = (req, res, next) => {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }

  try {
    req.user = verifyToken(token);
    next();
  } catch (err) {
    console.error('[AUTH] Invalid JWT:', err.message);
    return res.status(401).json({ error: 'Unauthorized: ' + err.message });
  }
};

// 2. ฟังก์ชันตรวจ Role (สำหรับ Admin)
const requireRole = (role) => {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ error: `Forbidden: ${role} only` });
    }
    next();
  };
};

module.exports = { requireAuth, requireRole };