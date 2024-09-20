const express = require('express')
const cors = require('cors');
const userRouter = require('./routes/userRoutes.js');
const cookieParser = require('cookie-parser');

const app = express();
app.use(cors({
    origin: 'http://localhost:3000',  // Replace this with your actual frontend URL
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => {
    console.log("welcome")
    res.status(200).send("Welcome")
})

app.use('/api/v1/users', userRouter);

module.exports = app;