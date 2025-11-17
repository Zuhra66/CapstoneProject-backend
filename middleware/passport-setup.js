// Passport configuration (Auth0 manages Google internally)
// middleware/passport-setup.js
// Placeholder file since Auth0 manages social connections.
const passport = require('passport');
module.exports = passport;

// Apple strategy — optional until you enable Apple login
if (process.env.APPLE_CLIENT_ID) {
  passport.use(new AppleStrategy({
    clientID: process.env.APPLE_CLIENT_ID,
    teamID: process.env.APPLE_TEAM_ID,
    callbackURL: `${process.env.AUTH0_BASE_URL}/auth/apple/callback`,
    keyID: process.env.APPLE_KEY_ID,
    privateKeyLocation: process.env.APPLE_PRIVATE_KEY
  }, (accessToken, refreshToken, idToken, profile, done) => {
    const email = idToken && idToken.email;
    return done(null, { email });
  }));
}

module.exports = passport;
