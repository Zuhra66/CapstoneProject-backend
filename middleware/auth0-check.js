const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');

const domain = process.env.AUTH0_DOMAIN;
const audience = process.env.AUTH0_AUDIENCE;

const getTokenFromCookie = (req) => {
  const cookieToken = req.cookies.access_token;
  const headerToken = req.headers.authorization;

  if (headerToken && headerToken.startsWith("Bearer ")) {
    return headerToken.replace("Bearer ", "");
  }

  if (cookieToken) {
    return cookieToken;
  }

  return null;
};

const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 10,
    jwksUri: `https://${domain}/.well-known/jwks.json`
  }),
  audience: audience,
  issuer: `https://${domain}/`,
  algorithms: ['RS256'],
  getToken: getTokenFromCookie
});

module.exports = checkJwt;