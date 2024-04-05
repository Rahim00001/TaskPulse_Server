const express = require('express');
const cors = require("cors");
require('dotenv').config()
const cookieParser = require("cookie-parser");
const app = express();
const port = process.env.PORT || 5000;
const connectDB = require('./src/db/connectDB');
const UserRouter = require("./src/routes/user")

// middleware
app.use(
    cors({
        origin: [process.env.LOCAL_CLIENT],
        credentials: true,
    })
);
console.log("apply middleware", process.env.LOCAL_CLIENT);
app.use(express.json());
app.use(cookieParser());


app.use('/auth', UserRouter)

app.get('/', (req, res) => {
    res.send('TaskPulse is working')
})

// basic error handling
app.all("*", (req, res, next) => {
    const error = new Error(`the requested error is invalid:  [${req.url}]`)
    error.status = 404
    next(error)
})

app.use((err, req, res, next) => {
    res.status(err.status || 5000).json({
        message: err.message
    })
})

const main = async () => {
    await connectDB()
    app.listen(port, () => {
        console.log('TaskPulse server is running on', port);
    })
}

main()