const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path'); // Added for serving static files
require('dotenv').config(); // Load environment variables

const app = express();
const PORT = process.env.PORT || 5000;

// Apply CORS middleware
app.use(cors({
  origin: function (origin, callback) {
    const allowedOrigins = ['http://192.168.1.7:3000', 'http://localhost:3000']; // Add all allowed origins here
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.error(`CORS error: Origin ${origin} not allowed`);
      callback(new Error('CORS policy: Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'], // Ensure all used methods are allowed
  credentials: true, // Include if using cookies or authentication headers
}));

// Parse incoming JSON requests
app.use(express.json());

// Serve uploaded files (avatars) statically
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Import and use routes
const todoRoutes = require('./routes/todos');
app.use('/api/todos', todoRoutes);

const authRoutes = require('./routes/auth');
app.use('/api/auth', authRoutes.router);

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI || 'mongodb+srv://nguyenlp:16012004@todoappdatabase.fid4v.mongodb.net/todo-app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('Connected to MongoDB');
}).catch((error) => {
  console.error('Error connecting to MongoDB:', error.message);
});

// Handle 404 errors for undefined routes
app.use((req, res, next) => {
  res.status(404).json({ message: 'Route not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Internal Server Error',
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});