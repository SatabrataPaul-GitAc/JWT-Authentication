const { verify } = require("jsonwebtoken");

const isAuth = (authorization) => {

        //Bearer vjcvgvcfki8t87t9t869yougf97uvg97t97fiugv
        const token = authorization.split(' ')[1];
        const data = verify(token,process.env.access_token_secret_key);

        return data.userId;
};

module.exports = isAuth;