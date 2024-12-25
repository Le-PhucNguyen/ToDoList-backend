const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5000;

// Apply CORS middleware
app.use(cors({
  origin: function (origin, callback) {
    const allowedOrigins = ['http://192.168.1.3:3000', 'http://localhost:3000']; // Add all allowed origins here
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'], // Added PATCH method here
  credentials: true, // Include if using cookies or authentication headers
}));

// Parse incoming JSON requests
app.use(express.json());

// Import and use routes
const todoRoutes = require('./routes/todos');
app.use('/api/todos', todoRoutes);

const authRoutes = require('./routes/auth');
app.use('/api/auth', authRoutes.router);

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/todo-app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', (error) => console.error('MongoDB connection error:', error));
db.once('open', () => console.log('Connected to MongoDB'));

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
