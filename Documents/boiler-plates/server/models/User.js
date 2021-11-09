const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10
const jwt =require('jsonwebtoken');

const userSchema = mongoose.Schema({
    name:{
        type: String,
        maxlenght: 50
    },
    email:{
        type: String,
        trim: true,
        unique: 1
    },
    password: {
        type: String,
        minlenght: 5
    },
    lastname:{
        type: String,
        maxlenght: 50
    },
    role:{
        type: Number,
        default: 0
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: {
        type: Number
    }
})

userSchema.pre('save', function( next ){
    let user = this;

    if(user.isModified('password')){
    
        //비밀번호를 암호화 시킨다.

        bcrypt.genSalt(saltRounds, function(err, salt){
            // bcrypt.hash(myPlaintextPassword, slat, function(err, hash){ });
            if(err) return next(err)

            bcrypt.hash(user.password, salt, function(err, hash){
                if(err) return next(err)
                user.password = hash
                next()
            })
        })
    } else {
        next()
    }
})

userSchema.methods.comparePassword = function(PlainPassword, cb) {
    //ex) plainPassword 1234567 ->> 암호화된 비밀번호 $2b$10$yHYL2WYTKfQYAq1sZU5gn
    bcrypt.compare(PlainPassword, this.password, function(err, isMatch){
        if(err) return cb(err)
            cb(null, isMatch)
    })
}

userSchema.methods.generateToken = function(cb){
    let user = this;
    // jsonwebtoken을 이용해서 token을 생성하기  
    let token = jwt.sign(user._id.toHexString(), 'secretToken')
    user.token = token
    user.save(function(err, user){
        if(err) return cb(err)
        cb(null, user)
    })
}

userSchema.statics.findByToken = function ( token, cb ){
    let user = this;

    // user._id + '' =  token;
    //토큰을 디코드 한다. 
    jwt.verify(token, 'secretToken', function(err, decoded){
        //user Id를 이용해서 user를 찾은 다음에 
        //client에서 가져온 Token과 DB에 보관된 Token 일치하는지 확인
        
        user.findOne({ "_id": decoded, "token": token }, function (err, user){
            if(err) return cb(err);
            cb(null, user)
        })
    })
}
const User = mongoose.model('User', userSchema)

module.exports = { User }