const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const JWT_SECRET = process.env.JWT_SECRET || 'vulnscan-pro-secret-key-change-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

function generateToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      role: user.role,
      email: user.email
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers && req.headers.authorization;
  const token = authHeader && authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    return next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    return next();
  };
}

async function hashPassword(password) {
  if (typeof password !== 'string' || !password.trim()) {
    throw new Error('Password is required');
  }

  return bcrypt.hash(password, 12);
}

async function comparePassword(password, hash) {
  if (typeof password !== 'string' || !hash) {
    return false;
  }

  return bcrypt.compare(password, hash);
}

module.exports = {
  generateToken,
  authenticateToken,
  requireRole,
  hashPassword,
  comparePassword,
  JWT_SECRET
};