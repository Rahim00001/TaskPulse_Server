const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');

router.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    const user = await User.findOne({ email })
    if (user) {
        return res.json({ message: "This user already existed" })
    }

    const hashpassword = await bcrypt.hash(password, 10)
    const newUser = new User({
        username,
        email,
        password: hashpassword,
    })
    await newUser.save()
    return res.json({ status: true, message: "record registerd" })
})
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email })
    if (!user) {
        return res.json({ message: "user is not registerd" })
    }
    const validPassword = await bcrypt.compare(password, user.password)
    if (!validPassword) {
        return res.json({ message: "password is incorrect" })
    }

    const token = jwt.sign({ username: user.username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' })
    res.cookie('token', token, { httpOnly: true, maxAge: 3600000 })
    return res.json({ status: true, message: "login successfully" })
})

module.exports = router