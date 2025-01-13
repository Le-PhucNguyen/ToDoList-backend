const express = require('express');
const router = express.Router();
const Todo = require('../models/Todo');
const { authenticateToken } = require('./auth');

// Fetch todos with filters, pagination, and soft delete exclusion
router.get('/', authenticateToken, async (req, res) => {
    try {
        const { search, completed, page = 1, limit = 10 } = req.query;

        const query = { userId: req.user.id, isDeleted: false }; // Exclude soft-deleted todos
        if (search) query.task = { $regex: search, $options: 'i' }; // Case-insensitive search
        if (completed !== undefined) query.completed = completed === 'true';

        const skip = (page - 1) * limit;
        const todos = await Todo.find(query).skip(skip).limit(Number(limit));
        const totalTodos = await Todo.countDocuments(query);

        res.json({
            todos,
            totalTodos,
            currentPage: Number(page),
            totalPages: Math.ceil(totalTodos / limit),
        });
    } catch (err) {
        res.status(500).json({ message: 'Error fetching todos', error: err.message });
    }
});

// Create a new todo
router.post('/', authenticateToken, async (req, res) => {
    try {
        const { task, completed } = req.body;

        if (!task || typeof task !== 'string' || task.trim() === '') {
            return res.status(400).json({ message: 'Invalid "task" field. It must be a non-empty string.' });
        }

        const todo = new Todo({
            task,
            completed: completed || false,
            userId: req.user.id,
            isDeleted: false,
        });

        const newTodo = await todo.save();
        res.status(201).json(newTodo);
    } catch (err) {
        res.status(400).json({ message: 'Error creating todo', error: err.message });
    }
});

// Update a todo
router.put('/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { task, completed } = req.body;

        if (task && (typeof task !== 'string' || task.trim() === '')) {
            return res.status(400).json({ message: 'Invalid "task" field. It must be a non-empty string.' });
        }

        const todo = await Todo.findOne({ _id: id, userId: req.user.id, isDeleted: false });
        if (!todo) {
            return res.status(404).json({ message: 'Todo not found or has been deleted' });
        }

        if (task) todo.task = task.trim();
        if (completed !== undefined) todo.completed = completed;

        const updatedTodo = await todo.save();
        res.json(updatedTodo);
    } catch (err) {
        res.status(400).json({ message: 'Error updating todo', error: err.message });
    }
});

// Delete a todo (soft or hard delete)
router.delete('/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { softDelete } = req.query;

        const todo = await Todo.findOne({ _id: id, userId: req.user.id });
        if (!todo) {
            return res.status(404).json({ message: 'Todo not found' });
        }

        if (softDelete === 'true') {
            todo.isDeleted = true;
            await todo.save();
            return res.json({ message: 'Todo soft deleted successfully' });
        } else {
            await todo.deleteOne();
            return res.json({ message: 'Todo deleted permanently' });
        }
    } catch (err) {
        res.status(500).json({ message: 'Error deleting todo', error: err.message });
    }
});

// Delete multiple todos (soft or hard delete)
router.delete('/', authenticateToken, async (req, res) => {
    try {
        const { ids } = req.body;
        const { softDelete } = req.query;

        if (!Array.isArray(ids) || ids.length === 0) {
            return res.status(400).json({ message: 'Invalid request, "ids" must be a non-empty array' });
        }

        const query = { _id: { $in: ids }, userId: req.user.id };

        if (softDelete === 'true') {
            await Todo.updateMany(query, { isDeleted: true });
            return res.json({ message: `${ids.length} todos soft deleted successfully` });
        } else {
            const result = await Todo.deleteMany(query);
            return res.json({
                message: `${result.deletedCount} todos deleted permanently`,
                deletedCount: result.deletedCount,
            });
        }
    } catch (err) {
        res.status(500).json({ message: 'Error deleting todos', error: err.message });
    }
});

// Undo soft delete a todo
router.patch('/undo-delete/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        const todo = await Todo.findOne({ _id: id, userId: req.user.id });
        if (!todo) {
            return res.status(404).json({ message: 'Todo not found' });
        }

        if (!todo.isDeleted) {
            return res.status(400).json({ message: 'Todo is not marked as deleted' });
        }

        todo.isDeleted = false;
        await todo.save();

        res.json({ message: 'Todo restored successfully', todo });
    } catch (err) {
        res.status(500).json({ message: 'Error restoring todo', error: err.message });
    }
});

module.exports = router;
