const express = require('express');
const router = express.Router();
const Todo = require('../models/Todo'); // Import the Todo model
const { authenticateToken } = require('./auth');

// Get todos for the logged-in user
router.get('/todos', authenticateToken, async (req, res) => {
    try {
      const { search, completed, page = 1, limit = 10 } = req.query;
  
      const query = { userId: req.user.id };
      if (search) query.task = { $regex: search, $options: 'i' };
      if (completed !== undefined) query.completed = completed === 'true';
  
      const skip = (page - 1) * limit;
      const todos = await Todo.find(query).skip(skip).limit(Number(limit));
      const totalTodos = await Todo.countDocuments(query);
  
      res.json({ todos, totalTodos, currentPage: page, totalPages: Math.ceil(totalTodos / limit) });
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  });
  
  // Create a todo for the logged-in user
  router.post('/todos', authenticateToken, async (req, res) => {
    try {
      const todo = new Todo({
        task: req.body.task,
        completed: req.body.completed || false,
        userId: req.user.id,
      });
  
      const newTodo = await todo.save();
      res.status(201).json(newTodo);
    } catch (err) {
      res.status(400).json({ message: err.message });
    }
  });

// Get all todos with search, filter, and pagination
router.get('/todos', async (req, res) => {
    try {
        const { search = '', completed, page = 1, limit = 10 } = req.query;

        // Build query object
        const query = {};
        if (search) {
            query.task = { $regex: search, $options: 'i' }; // Case-insensitive search
        }
        if (completed !== undefined) {
            query.completed = completed === 'true'; // Convert string to boolean
        }

        // Pagination
        const skip = (page - 1) * limit;

        // Fetch data with query, pagination, and sorting
        const todos = await Todo.find(query).skip(skip).limit(Number(limit));
        const totalTodos = await Todo.countDocuments(query); // Total number of matching todos

        res.json({
            todos,
            totalTodos,
            currentPage: Number(page),
            totalPages: Math.ceil(totalTodos / limit),
        });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Create a new todo
router.post('/todos', async (req, res) => {
    const { task, completed = false } = req.body;

    if (!task || typeof task !== 'string') {
        return res.status(400).json({ message: 'Task is required and must be a string' });
    }

    try {
        const todo = new Todo({
            task,
            completed,
        });

        const newTodo = await todo.save();
        res.status(201).json(newTodo);
    } catch (err) {
        res.status(500).json({ message: 'Error creating todo', error: err.message });
    }
});

// Update a todo
router.put('/todos/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { task, completed } = req.body;

        const todo = await Todo.findById(id);
        if (!todo) {
            return res.status(404).json({ message: 'Todo not found' });
        }

        if (task) {
            todo.task = task;
        }
        if (completed !== undefined) {
            todo.completed = completed;
        }

        const updatedTodo = await todo.save();
        res.json(updatedTodo);
    } catch (err) {
        res.status(400).json({ message: 'Error updating todo', error: err.message });
    }
});

// Delete a todo
router.delete('/todos/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const todo = await Todo.findById(id);
        if (!todo) {
            return res.status(404).json({ message: 'Todo not found' });
        }

        await todo.remove();
        res.json({ message: 'Todo deleted successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Error deleting todo', error: err.message });
    }
});

module.exports = router;
