const passport = require ('passport');
const GoogleStrategy = require ('passport-google-oauth2').Strategy;
//require ('dotenv').config ();
//const mongoURL = 'mongodb://127.0.0.1:27017/nodeproject';




passport.use (
  new GoogleStrategy (
    {
      clientID: '376473427577-tqumgaq34q4hh0skatmq6vih7lbjfest.apps.googleusercontent.com',
      clientSecret: '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',
      callbackURL: 'https://nodejsvickytest.onrender.com/auth/google/callback',//http://localhost:5000/auth/google/callback
      passReqToCallback: true,
    },
    function (request, accessToken, refreshToken, profile, done) {
      done (null, profile);
    }
  )
);

passport.serializeUser ((user, done) => {
  done (null, user);
});

passport.deserializeUser ((user, done) => {
  done (null, user);
});
