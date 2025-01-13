const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const winston = require('winston');
const User = require('../models/User');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const SECRET_KEY = process.env.JWT_SECRET || 'your-secret-key';

// Logger for error handling
const logger = winston.createLogger({
  level: 'error',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log' }),
  ],
});

// Rate limiter for authentication routes
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: { message: 'Too many requests, please try again later' },
  skip: (req) => req.path === '/auth/validate-token', // Skip specific route
});

// Random password generator function
const generateRandomPassword = (length = 12) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+';
  let password = '';
  for (let i = 0; i < length; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return password;
};

// Configure multer for local file storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, '../uploads/avatars')); // Save files in uploads/avatars
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`); // Unique filename with timestamp
  },
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|jfif/; // Added jfif support
    const isValidType = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    if (isValidType) {
      cb(null, true);
    } else {
      cb(new Error('Only .jpeg, .jpg, .png, and .jfif files are allowed'));
    }
  },
});

// Register a new user
router.post('/register', limiter, async (req, res) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
      return res.status(400).json({ success: false, message: 'Username, email, and password are required' });
    }
    if (username.length < 3) {
      return res.status(400).json({ success: false, message: 'Username must be at least 3 characters long' });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters long' });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Username already exists' });
    }

    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      password: hashedPassword,
      email,
      profile: {
        bio: '',
        avatar: '/uploads/avatars/default-avatar.png', // Default avatar
      },
    });
    await user.save();

    res.status(201).json({ success: true, message: 'User registered successfully' });
  } catch (err) {
    logger.error(err.message, { stack: err.stack });
    res.status(500).json({ success: false, message: 'Error registering user' });
  }
});

// Login a user
router.post('/login', limiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password are required' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ success: true, message: 'Login successful', token, expiresIn: '1h' });
  } catch (err) {
    logger.error(err.message, { stack: err.stack });
    res.status(500).json({ success: false, message: 'Error logging in' });
  }
});

// Forgot Password Route
router.post('/forgot-password', limiter, async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, message: 'Email is required' });
  }

  try {
    console.log('Processing password reset for email:', email);

    const user = await User.findOne({ email });
    if (!user) {
      console.log('Email not found in the database');
      return res.status(404).json({ success: false, message: 'Email not found' });
    }

    const newPassword = generateRandomPassword();
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    await user.save();

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: `"Your App Name" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Password Reset Request',
      html: `
        <p>Your new password is:</p>
        <p><b>${newPassword}</b></p>
        <p>Please log in and change your password immediately.</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    console.log('Password reset email sent to:', email);

    res.status(200).json({ success: true, message: 'New password sent to your email address' });
  } catch (error) {
    console.error('Error during password reset:', error);
    logger.error(error.message, { stack: error.stack });
    res.status(500).json({ success: false, message: 'Error processing password reset request' });
  }
});

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Unauthorized: Missing or invalid token' });
  }

  const token = authHeader.split(' ')[1];
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Change Password Route
router.put('/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword, confirmNewPassword } = req.body;

  if (!currentPassword || !newPassword || !confirmNewPassword) {
    return res.status(400).json({ success: false, message: 'All fields are required' });
  }

  if (newPassword !== confirmNewPassword) {
    return res.status(400).json({ success: false, message: 'New passwords do not match' });
  }

  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Current password is incorrect' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ success: false, message: 'New password must be at least 6 characters long' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.status(200).json({ success: true, message: 'Password updated successfully' });
  } catch (err) {
    logger.error(err.message, { stack: err.stack });
    res.status(500).json({ success: false, message: 'Error updating password' });
  }
});

// Validate token
router.post('/validate-token', async (req, res) => {
  const token = req.body.token || req.header('Authorization')?.split(' ')[1];

  if (!token) {
    return res.status(400).json({ success: false, message: 'Token is required' });
  }

  jwt.verify(token, SECRET_KEY, async (err, decoded) => {
    if (err) {
      return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }

    try {
      const user = await User.findById(decoded.id).select('-password');
      if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }

      res.status(200).json({ success: true, message: 'Token is valid', user });
    } catch (error) {
      logger.error(error.message, { stack: error.stack });
      res.status(500).json({ success: false, message: 'Error validating token' });
    }
  });
});

// Get user profile
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    res.json({ success: true, user });
  } catch (err) {
    logger.error(err.message, { stack: err.stack });
    res.status(500).json({ success: false, message: 'Error retrieving user profile' });
  }
});

// Update user profile (including avatar upload)
router.put('/profile', authenticateToken, (req, res, next) => {
  upload.single('avatar')(req, res, (err) => {
    if (err && (err instanceof multer.MulterError || err.message)) {
      return res.status(400).json({ success: false, message: err.message });
    }
    next();
  });
}, async (req, res) => {
  try {
    const { bio } = req.body;
    const updatedFields = {};

    if (bio !== undefined) updatedFields['profile.bio'] = bio;

    if (req.file) {
      updatedFields['profile.avatar'] = `/uploads/avatars/${req.file.filename}`;
    }

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { $set: updatedFields },
      { new: true, runValidators: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({ success: true, user });
  } catch (err) {
    logger.error(err.message, { stack: err.stack });
    res.status(500).json({ success: false, message: 'Error updating profile' });
  }
});

module.exports = { router, authenticateToken };
