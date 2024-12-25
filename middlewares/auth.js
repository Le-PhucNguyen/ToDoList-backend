const jwt = require('jsonwebtoken');

// Middleware to authenticate requests using JWT
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1]; // Extract Bearer token
  if (!token) return res.status(401).json({ message: 'Access Denied' });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key'); // Verify the token
    req.user = verified; // Attach user info to the request object
    next();
  } catch (err) {
    res.status(403).json({ message: 'Invalid Token' });
  }
};

// Example placeholder for another middleware (existing functionality)
const exampleMiddleware = (req, res, next) => {
  console.log('Example middleware executed');
  next();
};

module.exports = {
  authenticateToken,
  exampleMiddleware, // Keep existing functions
};
