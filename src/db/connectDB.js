const mongoose = require('mongoose');
require('dotenv').config()

const getConnectionUri = () => {
    let connectionURI;
    if (process.env.NODE_ENV === 'development') {
        connectionURI = process.env.DB_LOCAL;
        connectionURI = connectionURI.replace('<username>', process.env.DB_USER)
        connectionURI = connectionURI.replace('<password>', process.env.DB_PASS)
    } else {
        connectionURI = process.env.DB_PROD
    }
    return connectionURI
}

const connectDB = async () => {
    console.log('connecting to database');
    const uri = getConnectionUri();
    await mongoose.connect(uri, { dbName: process.env.DB_NAME })
    console.log('connected to database');
}

module.exports = connectDB