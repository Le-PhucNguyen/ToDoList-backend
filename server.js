const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors({}));
app.use(express.json());

const todoRoutes = require('./routes/todos');
app.use('/api', todoRoutes);

const authRoutes = require('./routes/auth');
app.use('/api/auth', authRoutes.router);


app.get('/', (req,res)=>{
  return res.send("hehe")
})

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/todo-app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', (error) => console.error(error));
db.once('open', () => console.log('Connected to MongoDB'));

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});