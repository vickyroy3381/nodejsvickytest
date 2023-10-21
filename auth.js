const passport = require ('passport');
const GoogleStrategy = require ('passport-google-oauth2').Strategy;
//require ('dotenv').config ();
//const mongoURL = 'mongodb://127.0.0.1:27017/nodeproject';




passport.use (
  new GoogleStrategy (
    {
      clientID: '969938984278-dr89d6qu6bv6ofc6l31qnq8mff4ou240.apps.googleusercontent.com',
      clientSecret: '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',
      callbackURL: 'http://localhost:5000/auth/google/callback',//http://localhost:5000/auth/google/callback
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
