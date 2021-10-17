require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const Users = require("../model/model.js");
const HTTPError = require("../errorMesage.js");
const {createAccessToken,createRefreshToken,sendAccessToken,sendRefreshToken} = require("./tokens.js");
const isAuth = require("./auth.js");


//MongoDB Connection
const mongoose = require("mongoose");
mongoose.connect(process.env.MONGO_DEV_URI, { useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true })
.then((result)=>{
    console.log("Server connected with MongoDB");
})
.catch((err)=>{
    console.log(err);
});

const app=express();

//Application Level Middlewares
app.use(cookieParser());
app.use(express.json()); //to support json bodies
app.use(express.urlencoded({extended: true})); // to support url-encoded bodies


//function for hashing the password
const hashPassword = function generateHash(password){
    try{
        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync(password,salt);
        return hashedPassword;
    }
    catch(err){
        console.log(err);
    }
}


//Registration Route
app.post("/register",(req,res)=>{
    try{
        const email = req.body.email;
        const name = req.body.name;
        let password = req.body.password;

        if(!email) throw  new HTTPError(400,"Email Not Found");
        if(!password) throw  new HTTPError(400,"Password not found");

        Users.findOne({email: email},(err,user)=>{
            if(user) res.status(400).json({status: "error",message: "User already exists"});

            else{
                password = hashPassword(password);
                console.log(password)
        
                const newUser = new Users({
                    email,
                    name,
                    password
                });

                newUser.save((err)=>{
                    if(err){
                        console.log(err);
                    }
                else{
                    res.status(200).json({status: "success",message: "User Registered Successfully"});
                }
            })
        }
    });

    }
    catch(err){
        return res.status(err.statusCode | 400).json({status: "error",message: err.message});
    }
});


//Login Route
app.post("/login",async (req,res)=>{
    try{
        const email = req.body.email;
        const password = req.body.password;

        if(!email) throw new HTTPError(400,"Email is required !");
        if(!password) throw new HTTPError(400,"Password is required !");

        let user = await Users.findOne({email: email}).exec();

        if(!user) throw new HTTPError(400,"User is not registered ! Login not possible");

        const valid = bcrypt.compareSync(password,user.password);

        if(!valid) throw new HTTPError(400,"Password is not correct");

        //Create an access and refresh token
        const accesstoken = createAccessToken(user.id,user.email);
        const refreshtoken = createRefreshToken(user.id,user.email);

        //Saving the refreshtoken in the database
        user.refreshToken = refreshtoken;
        await user.save();

        //Sending the refresh token back to client side as a cookie 
        //and the access token as a regular response after the authentication)login has been done)
        sendAccessToken(req,res,accesstoken);
        sendRefreshToken(res,refreshtoken);

    }
    catch(err){
        res.status(err.statusCode | 400).json({status: "error",message: err.message});
    }
});


//Logout route
app.post("/logout",(_req,res)=>{
    res.clearCookie("RefreshToken");
    res.status(200).json({status: "success",message: "Successfully loggedout"});
});


//Protected route which checks whether the user is authenticated or logged in or not
app.post("/protected",(req,res) =>{
    try{
        const authorization = req.header("authorization");

        if(!authorization) throw new HTTPError(400,"Login is required !");

        const userID = isAuth(authorization);

        if(userID!=null){
            Users.findById(userID,(err,docs)=>{
                if(err){
                    console.log(err);
                }
                else{
                    console.log(docs.email);
                    res.json({message: "Access granted to protected route",emailID: docs.email});
                }
            });
        }
    }
    catch(err){
        res.status(err.statusCode | 400).json({status: "error",message: err.message});
    }
});

app.listen(process.env.PORT,()=>{
    console.log(`Server started of port ${process.env.PORT}`)
});






