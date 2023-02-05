const express = require('express')
const path = require('path')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const user = require('./model/user')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

//create secret
const JWT_SECRET = 'sdfjafjoasi!@#$%fjaoidfadksf'

mongoose.connect('mongodb://127.0.0.1:27017/login-app-db', {
    //useNewUrlParser: true,
    //useUnifiedTopology: true
    //useCreateIndex: true
}) //몽구스 연결하기

mongoose.set("strictQuery", false)

const app = express()
app.use('/', express.static(path.join(__dirname, 'static')))
app.use(bodyParser.json())

//비밀번호 변경하기
app.post('/api/change-password', async (req, res) => {
    const { token, newpassword: plainTextPassword } = req.body

    if (!plainTextPassword || typeof plainTextPassword !== 'string') {
        return res.json({ status: 'error', error: 'Invalid password' })
    }

    if (plainTextPassword.length < 5) {
        return res.json({
            status: 'error',
            error: 'Password too small. Should be atleast 6 characters'
        })
    }

    try {
        const user = jwt.verify(token, JWT_SECRET)

        const _id = user.id

        const password = await bcrypt.hash(plainTextPassword, 10)

        await User.updateOne(
            { _id },
            {
                $set: { password }
            }
        )
        res.json({ status: 'ok' })
    } catch (error) {
        console.log(error)
        res.json({ status: 'error', error: ';))' })
    }
})

//로그인하기
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body
    const user = await user.findOne({ username, password }).lean

    if (!user) {
        return res.json({ status: 'error', error: 'Invalid username/password' })
    }

    if (bcrypt.compare(password, user.password)) {
        //the username, password combination is successful

        const token = jwt.sign({ id: user.id, username: user.username },
            JWT_SECRET

        )

        return res.json({ status: 'ok', data: '' })
    }
    res.json({ status: 'error', error: 'Invald username/password' })
})

app.post('/api/register', async (req, res) => {
    const { username, password: plainTextPassword } = req.body

    //잘못된 정보 입력하는 경우 메시지를 나타내도록 함.
    if (!username || typeof username !== 'string') {
        return res.json({ status: 'error', error: 'Invalid username' })
    }
    if (!plainTextPassword || typeof plainTextPassword !== 'string') {
        return res.json({ status: 'error', error: 'Invalid password' })
    }
    if (plainTextPassword.length < 5) {
        return res.json({ status: 'error', error: 'Passwords should be longer.' })
    }

    //보안을 위해 password hashing 진행하기
    //대표적인 hashing algorithm function: bcrypt, md5, shal, sha256, sha512, ...
    // console.log(await bcrypt.hash(password, 10))
    //해싱된 패스워드 password
    const password = await bcrypt.hashSync(plainTextPassword, 10)
    try {
        const response = await user.create({
            username,
            password
        })
        console.log('User created successfully', response)
    } catch (error) {
        // console.log(JSON.stringify(error.message))
        if (error.code === 11000) {
            //중복된 key값
            return res.json({ status: 'error', error: 'Username already in use.' })
        }
        throw error
        // return res.json({ status: 'error' })
    }

    res.json({ status: 'ok' })
})

app.listen(9999, () => {
    console.log('Server up at 9999')
})