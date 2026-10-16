const jwt = require('jsonwebtoken');

function verifyToken(token) {
  // CWE-347: Improper Verification of Cryptographic Signature
  // Flaw: verify is called with 'none' algorithm allowed and no secret provided
  return jwt.verify(token, '', { algorithms: ['none'] });
}

module.exports = { verifyToken };