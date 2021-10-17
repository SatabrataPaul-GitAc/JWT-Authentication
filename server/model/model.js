const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const userSchema = new Schema({
    email: {
        type: String,
        required: true
    },
    name: {
        type: String,
    },
    password: {
        type: String,
        required: true 
    },
    refreshToken:{
        type: String
    }
});

module.exports = mongoose.model("userdata",userSchema);