const { verifyToken } = require('./jwtUtils');

function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }
  
  try {
    req.user = verifyToken(token);
    next();
  } catch (err) {
    console.error('[AUTH MIDDLEWARE] Invalid JWT:', err.message);
    return res.status(401).json({ error: 'Unauthorized: ' + err.message });
  }
}

// 💡 เพิ่มฟังก์ชันนี้เข้าไปให้ใช้งานได้
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
    }
    next();
  };
}

module.exports = { requireAuth, requireRole };