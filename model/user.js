const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, require: true }
},
    { collection: 'users' }
)

const model = mongoose.model('userSchema', userSchema)

module.exports = model