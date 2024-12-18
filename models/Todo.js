const mongoose = require('mongoose');

const todoSchema = new mongoose.Schema({
  task: { type: String, required: true },
  completed: { type: Boolean, default: false },
  isDeleted: { type: Boolean, default: false }, // Soft delete flag
}, { timestamps: true });

const Todo = mongoose.model('Todo', todoSchema);

module.exports = Todo;
