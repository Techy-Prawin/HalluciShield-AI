const jwt = require('jsonwebtoken');

function verifyToken(token) {
  // CWE-347: Insecure JWT - Algorithm set to 'none' and no secret provided
  const decoded = jwt.verify(token, '', { algorithms: ['none'] });
  return decoded;
}

module.exports = { verifyToken };