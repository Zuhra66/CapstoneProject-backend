const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');

const AUTH0_DOMAIN = 'dev-u7gbqtzuy3mibb7f.us.auth0.com';
const AUDIENCE = 'https://empowermed-backend.onrender.com';

const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 10,
    jwksUri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`
  }),
  audience: AUDIENCE,
  issuer: `https://${AUTH0_DOMAIN}/`,
  algorithms: ['RS256']
});

const requireAdmin = (req, res, next) => {
  const roles = req.auth['https://empowermed-backend.onrender.com/roles'] || [];
  if (!roles.includes('admin')) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

module.exports = { checkJwt, requireAdmin };
