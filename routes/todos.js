const express = require('express');
const router = express.Router();
const Todo = require('../models/Todo');
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

// Delete multiple todos
router.delete('/todos', async (req, res) => {
    try {
        const { ids } = req.body;

        if (!Array.isArray(ids) || ids.length === 0) {
            return res.status(400).json({ message: 'Invalid request, "ids" must be a non-empty array' });
        }

        const result = await Todo.deleteMany({ _id: { $in: ids } });

        res.json({
            message: `${result.deletedCount} todos deleted successfully`,
            deletedCount: result.deletedCount,
        });
    } catch (err) {
        res.status(500).json({ message: 'Error deleting todos', error: err.message });
    }
});

module.exports = router;
