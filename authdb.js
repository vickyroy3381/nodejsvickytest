const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const authSchema = new Schema({
    googleId: String, // Unique identifier from Google
    username: String,
    email: String,
});

module.exports = mongoose.model("auth", authSchema);
