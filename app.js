const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
//const MemoryStore = require('memorystore')(session);
const passport = require('passport');
const bcrypt = require('bcrypt');
const path = require ('path');
const LocalStrategy = require('passport-local').Strategy;
const flash = require('connect-flash');
const User = require('./User');
const Token=require('./token');
const auth=require('./authdb');
const axios = require('axios');
const Recaptcha = require('express-recaptcha').RecaptchaV3;
require ('./auth');

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const transporter = require('./nodemailer-config'); //  Nodemailer configuration




const app = express();
app.set('views', path.join(__dirname, 'views'));

const recaptchaSiteKey = '6Lfkp5MoAAAAADZFTt6gTxwbuwyS-uZG9Vqud7dZ';

// MongoDB connection
mongoose.connect('mongodb+srv://vickyjsauth:PZxeE0vvWdbZn9fw@mymongodb.mecwaj1.mongodb.net/mymongodb?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Express middlewares
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'secret-key', resave: true, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// Passport configuration
passport.use(
    new LocalStrategy(async (username, password, done) => {
      try {
        const user = await User.findOne({ username: username });
        if (!user) return done(null, false, { message: 'User not found.' });
        if (!user.validPassword(password)) return done(null, false, { message: 'Invalid password.'});
        //console.log(username, password);
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    })
  );
  

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  });

// Routes
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/home.html');
  });

  //const secretKey = '6Lfkp5MoAAAAAB71Hzi4w8YkWvHG5dhTRqrabdee';

app.get('/register', (req, res) => {
    res.render( 'register.ejs', { recaptchaSiteKey });
});

app.post('/register', async (req, res) => {
  const { username, password, 'g-recaptcha-response': recaptchaToken } = req.body;

  // Verify reCAPTCHA response
  const secretKey = '6Lfkp5MoAAAAAB71Hzi4w8YkWvHG5dhTRqrabdee'; // Replace with your reCAPTCHA secret key
  const verificationURL = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${recaptchaToken}`;
  
  try{
      const response = await axios.post(verificationURL);
      if (response.data.success) {
          // Registration logic
          const newUser = new User({ username: req.body.username });
          newUser.password = newUser.generateHash(req.body.password);
          newUser.save()
          .then(() => {
            res.redirect('/login');
          })
          .catch((err) => {
            // Handle the error (e.g., log it or send an error response)
            console.error(err);
            res.status(500).send('Internal Server Error');
          });
        } else {
          // Handle the case where reCAPTCHA verification fails
          res.status(400).send('reCAPTCHA verification failed');
        }
      } catch (error) {
        console.error(error);
        // Handle other potential errors (e.g., network issues)
        res.status(500).send('An error occurred');
      }
        
      });


app.get('/login', (req, res) => {
     const messages = req.flash();
     res.render('login.ejs',{messages});
});
app.post('/login', async (req, res) => {
  const { username, password, 'g-recaptcha-response': recaptchaToken } = req.body;

  // Verify reCAPTCHA response
  const secretKey = '6Lfms88oAAAAACJpb__0N22L2uZNwaJelPud1qKP'; // Replace with your reCAPTCHA secret key
  const verificationURL = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${recaptchaToken}`;

  try {
      const response = await axios.post(verificationURL);
      if (response.data.success) {
          // ReCAPTCHA verification successful, proceed with Passport.js authentication
          passport.authenticate('local', {
              successRedirect: '/dashboard',
              failureRedirect: '/login',
              failureFlash: true,
          })(req, res);
      } else {
          // If reCAPTCHA verification fails
          res.redirect('/login');
      }
  } catch (error) {
      console.error(error);
      // Handle error
  }
});




//Google auth2
app.get (
  '/auth/google',
  passport.authenticate ('google', {
    scope: ['email', 'profile'],
  })
);

app.get (
  '/auth/google/callback',
  passport.authenticate ('google', {
    successRedirect: '/dashboard',
    failureRedirect: '/auth/google/failure',
  })
);

app.get ('/auth/google/failure', (req, res) => {
  res.send ('Something went wrong!');
});



//new goggle auth// Inside the Google OAuth2.0 callback route
app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  async (req, res) => {
      try {
          // Check if the user already exists in the database
          const existingUser = await User.findOne({ googleId: req.user.id });

          if (!existingUser) {
              // Create a new user record if it doesn't exist
              const newUser = new auth({
                  googleId: req.user.id,
                  username: req.user.username,
                  email: req.user.emails[0].value,
              });

              await newUser.save();
          }

          // Store the user data in the session
          req.session.user = req.user;

          res.redirect('/dashboard');
      } catch (err) {
          console.error('Error saving user data:', err);
          res.redirect('/');
      }
  }
);

app.get('/dashboard', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('dashboard.ejs',{name: req.user.username});
  } else {
    res.redirect('/login');
  }
});


app.get('/logout', (req, res) => {
    req.logout((err) => {
      if (err) {
        //to  Handle errors that may occur during logout
        console.error(err);
      }
      
      res.redirect('/'); // Redirect to the home page or another appropriate page
    });
  });




  app.get('/forgot-password', (req, res) => {
    res.sendFile(__dirname + '/forgot-password.html');
});


 // Import your Nodusernameer configuration
  
  app.post('/forgot-password', async (req, res) => {
    const username = req.body.username;
    const user = await User.findOne({ username });
    console.log(username);
  
    if (!user) {
      // Handle the case where the username address is not found
      return res.status(404).send('username not found');
    }
  
    // Generate a random token
   
    let token = await Token.findOne({ userId: user._id });
        if (!token) {
            token = await new Token({
                userId: user._id,
                token: crypto.randomBytes(32).toString("hex"),
            }).save();
            //console.log();
        }
  
    // Send the reset password link via username
    const resetLink = `http://localhost:3000/reset-password/${user._id}/${token.token}`;
    const mailOptions = {
      from:'venkatanagireddy3381@gmail.com',
      to: username,
      subject: 'Password Reset',
      text: `To reset your password, click on the following link: ${resetLink}`,
    };
  
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error(error);
        return res.status(500).send('Error sending username');
      }
      console.log(`username sent: ${info.response}`);
      res.status(200).send('Password reset username sent');
    });
  });

  

  //2
  app.get('/reset-password/:userId/:token', async (req, res) => {
    const token = req.params.token;
    const userId = req.params.userId;
    const user = await User.findById(req.params.userId);
    
    // Check if the token is valid and not expired
    if (!user) return res.status(400).send("invalid link or expired");
    const token_rec = await Token.findOne({
      userId: user._id,
      token: req.params.token,
  });
  if (!token_rec) return res.status(400).send("Invalid link or expired");
    
   
    // Render the reset password page with the token
    res.render("reset-password.ejs", {userId, token, message: req.flash('message') });
    

  });
  
  app.post('/reset-password/:userId/:token', async (req, res) => {
    const userId = req.params.userId;
    const token = req.params.token;
    const newPassword = req.body.newPassword;
    const confirmPassword = req.body.confirmPassword;
    
    // Check if the token is valid and not expired
    // ...
  
    if (newPassword !== confirmPassword) {
      req.flash('message', 'Passwords do not match.');
      return res.redirect(`/reset-password/${userId}/${token.token}`);
    }
    
    try {
      // Check if the token is valid and not expired
     
      const user = await User.findById(req.params.userId);
      if (!user) return res.status(400).send("invalid link or expired aaaaaaaaa...");
      const token_rec = await Token.findOne({
        userId: user._id,
        token: token,
      });
      if (!token_rec) return res.status(400).send("Invalid link or expired");
        if (newPassword !== confirmPassword) {
          // Handle password mismatch
          return res.status(400).send('Passwords do not match');
        }

        // Hash the new password securely
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the user's password and clear token-related fields
        user.password =hashedPassword;
        await user.save();
        const tokenIdToDelete = 'token_rec';

// Use the findByIdAndRemove or deleteOne method to delete the record
      try {
        const deletedToken = await Token.findByIdAndRemove(tokenIdToDelete);
        if (!deletedToken) {
          // Handle the case where the token was not found
          console.log('Token not found');
        } else {
          // Token deleted successfully
          console.log('Token deleted successfully');
        }
      } catch (err) {
        console.error(err);
        // Handle the error appropriately
      }


        req.flash('message', 'Password reset successfully.');
        res.redirect('/login');
      
    } catch (error) {
      console.error(error);
      // Handle any errors that occur during the process
      res.status(500).send('An error occurred while resetting the password');
    }

   
  });

  
  
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
