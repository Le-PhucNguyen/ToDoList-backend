const mongoose = require('mongoose');

const todoSchema = new mongoose.Schema(
  {
    task: { type: String, required: true, trim: true }, // Trim whitespace from task
    completed: { type: Boolean, default: false },
    isDeleted: { type: Boolean, default: false }, // Soft delete flag
    userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' }, // Associate todos with a user
  },
  { timestamps: true } // Adds createdAt and updatedAt fields
);

// Middleware to ensure `task` is always trimmed before saving
todoSchema.pre('save', function (next) {
  if (this.task) {
    this.task = this.task.trim();
  }
  next();
});

const Todo = mongoose.model('Todo', todoSchema);

module.exports = Todo;
