const {sign} = require("jsonwebtoken");


//function for creating access token
const createAccessToken = (userId,email) => {
    return sign({userId: userId,email: email},process.env.access_token_secret_key,{
        expiresIn: '20m'
    })
};

//function for creating refresh token
const createRefreshToken = (userId,email) => {
    return sign({userId: userId,email: email},process.env.refresh_token_secret_key,{
        expiresIn: '7d'
    })
};

//function for sending access token back to client
const sendAccessToken = (req,res,accesstoken) =>{
    res.status(200).json({
        accessToken: accesstoken,
        email: req.body.email
    })
};


//function for sending refresh token as a cookie
const sendRefreshToken = (res,refreshtoken) => {
    res.cookie("RefreshToken",refreshtoken,{
        httpOnly: true,
        path: "/refresh_token"
    });
};


//exporting functions for usage in index.js file
module.exports = {
    createAccessToken,
    createRefreshToken,
    sendAccessToken,
    sendRefreshToken
};


