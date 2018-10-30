var express = require('express');
var router = express.Router();

const User = require('../../models/Users');
const gravatar = require('gravatar');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// 引入验证方法
const validateRegisterInput = require('../../validation/register');
const validateLoginIpt = require('../../validation/login');

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('this is users API');
});

// $router POST api/users/register
// @desc 返回的请求的json数据
// @access public
router.post('/register', (req, res, next) => {
  const {errors, isValid} = validateRegisterInput(req.body);
  if(!isValid) return res.status(400).json({errors});
  
  User.findOne({
    email: req.body.email
  }).then(user => {
    if (user) {
      res.status(400).json({email: '邮箱已被注册'});
      return;
    }
    const avatar = gravatar.url(req.body.email, {s: '200',r: 'G',d: 'mm'});
    const newUser =  new User({
      name: req.body.name,
      email: req.body.email,
      password: req.body.password,
      password2: req.body.password2,
      avatar
    });

    // 加密密码
    bcrypt.genSalt(10, (err, salt) => {
      bcrypt.hash(newUser.password, salt, (err, hash) => {
        if(err) throw err;
        newUser.password = hash;

        newUser.save().then(user => {
          res.status(200).json(user);
        }).catch(err => {
          throw err;
        })
      });
    })
 
  }).catch(err => {
    throw err;
  })
});

// $router GET api/users/login
// @desc 返回token jwt passport
// @access public
router.get('/login',(req, res, next) =>{
  const {
    errors,
    isValid
  } = validateLoginIpt(req.body);
  if(!isValid) return res.status(400).json(errors);
  const email = req.body.email;
  const password = req.body.password;
  User.findOne({email}).then(user => {
    if(!user) return res.status(404).json({email: '用户不存在！'});
    bcrypt.compare(password, user.password).then(isMatch =>{
      if(isMatch){
        // 定义token
        const rule = {
          id: user.id,
          name: user.name
        };
        // jwt.sign('规则', '加密名字', '过期时间', '回调函数')
        jwt.sign(rule, 'secret', {expiresIn: 3600}, (err, token) => {
          if(err) throw err;
          res.status(200).json({
            sucess: true,
            token: "Bearer " + token,
          });
        })
      }else{
        return res.status(400).json({
          password: '密码错误！'
        });
      }
    })
  })
});
module.exports = router;
