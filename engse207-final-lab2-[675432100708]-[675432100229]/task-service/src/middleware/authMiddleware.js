const { verifyToken } = require('./jwtUtils');

module.exports = function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }
  
  try {
    req.user = verifyToken(token);
    next();
  } catch (err) {
    // 💡 Set 2: ลบการยิง API ไปหา log-service ทิ้ง แล้วเปลี่ยนมา log ลง console ของตัวเองแทน
    console.error('[AUTH MIDDLEWARE] Invalid JWT:', err.message);
    
    return res.status(401).json({ error: 'Unauthorized: ' + err.message });
  }
};