const jwt = require('jsonwebtoken');

function verifyToken(token) {
  // CWE-347: Insecure JWT Verification
  // Flaw: Using 'none' algorithm allows unsigned tokens to be accepted
  const decoded = jwt.verify(token, 'weak-secret', { algorithms: ['none'] });
  return decoded;
}

module.exports = { verifyToken };