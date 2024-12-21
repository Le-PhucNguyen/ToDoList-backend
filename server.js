const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5000;

// Apply CORS middleware
app.use(cors({
  origin: 'http://localhost:3000', // Or your frontend's deployment URL
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
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
