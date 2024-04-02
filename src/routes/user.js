const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const User = require('../models/User')

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
    return res.json({ message: "record registerd" })
})

module.exports = router