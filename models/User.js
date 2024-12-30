const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true }, // Added email field
  password: { type: String, required: true },
  profile: {
    bio: { type: String, default: '' }, // Optional bio field
    avatar: { type: String, default: '' }, // Optional avatar field (URL or file path)
  },
});

// Method to compare passwords (existing functionality)
userSchema.methods.comparePassword = function (password) {
  return bcrypt.compare(password, this.password);
};

module.exports = mongoose.model('User', userSchema);
