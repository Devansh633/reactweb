require('dotenv').config();
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');

const bcrypt = require('bcryptjs');
const saltRound = 10;

const jwt = require('jsonwebtoken');

const app = express();


app.use(express.json());
app.use(cors({
    origin:["http://localhost:3000"],
    methods:["GET","POST"],
    credentials: true
}));

app.use(cookieParser());
//app.use(bodyParser.urlencoded({ extended: true }));

app.use (
    session ({
        key: "userId",
        secret: "legion633",
        resave: false,
        saveUninitialized: false,
        cookie: {
            expires: 60 * 60 * 24,
        },
    })
);

 const db = mysql.createConnection({
    user:"root",
    host:"localhost",
    password:"legion633",
    database:"loginsystem"
 });

app.post('/signup',(req,res)=>{

    const name = req.body.name
    const email = req.body.email
    const password = req.body.password
    const role = "user"

    bcrypt.hash(password,saltRound, (err, hash) => {
        if (err) {
                 console.log(err)
             }

        db.query("INSERT INTO loginuser(user_name,user_email,user_password,user_role) VALUES (?,?,?,?)",
        [name,email,hash,role], (err, result) => {
            console.log(err);
        });
    })
 });

app.get("/login",(req,res) => {
    if(req.session.user){
        res.send({loggedIn:true,user:req.session.user})
    }else{
        res.send({loggedIn:false})
    }
});


app.post('/login',(req,res)=>{

    const email = req.body.email
    const password = req.body.password

    db.query("SELECT *FROM loginuser WHERE user_email=?;",email,
    (err, result) => {

        if(err){
            res.send({err:err})
        }

        if(result.length > 0){
            bcrypt.compare(password,result[0].user_password, (error, response) => {
                if (response) {
                    const id = result[0].user_id;
                    const token = jwt.sign({id},process.env.SECRET_KEY,{
                        expiresIn: 30000
                    })
                    
                    res.cookie("jwt",token,{
                        expires:new Date(Date.now() + 300000),
                        httpOnly:true
                    });
                    req.session.user = result;
                    console.log(req.session.user);
                    res.json({auth: true, token: token, result: result});
                    
                } else{
                    res.send({message: "Wrong username/ password combination!"}); 
                }
            });
        }else{
            res.send({message: "User doesn't exist "});
        }       
    });
 });

 app.get('/logout',(req,res) =>{
    res.clearCookie('userId');
    res.session.destroy();
 })


app.listen(3001, () => {
    console.log("running server");
});
