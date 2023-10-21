// nodemailer-config.js

//nodemailer configuration
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  port: 587, 
  secure:true,
  logger:true,// e.g., 'Gmail'
  auth: {
    user: 'venkatanagireddy3381@gmail.com',
    pass: 'yzjjdgbegvjaaier',
  },
  tls:{
    rejectUnauthorized:true
  }
});





module.exports = transporter;
