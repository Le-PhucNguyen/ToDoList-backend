const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1]; // Extract Bearer token
  if (!token) return res.status(401).json({ message: 'Access Denied' });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified; // Attach user info to the request object
    next();
  } catch (err) {
    res.status(403).json({ message: 'Invalid Token' });
  }
};

module.exports = authenticateToken;
