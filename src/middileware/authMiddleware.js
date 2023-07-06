const jwt = require('jsonwebtoken');
const secretKey = require('../users/secrets/secret');

// Middleware to authenticate requests using JWT
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization;

  if (token && token.startsWith('Bearer ')) {
    const bearerToken = token.slice(7); // Remove "Bearer " from the token string

    try {
      const decodedToken = jwt.verify(bearerToken, secretKey);
      // Assuming the payload should have "issuer" and "id" fields
      const { issuer, id } = decodedToken;

      if (issuer === 'userreadonly' && id === '1') {
        req.user = decodedToken;
        next();
      } else {
        return res.sendStatus(403); // Invalid issuer or id
      }
    } catch (err) {
      return res.sendStatus(401); // Invalid token
    }
  } else {
    res.sendStatus(401); // No or invalid Bearer token
  }
};

module.exports = authenticateJWT;
