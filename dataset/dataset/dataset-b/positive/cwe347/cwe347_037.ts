const jwt = require('jsonwebtoken');

function authenticate(token) {
  // CWE-347: Improper Verification of Cryptographic Signature
  // Flaw: verify is called with 'none' algorithm allowed and no secret provided
  const decoded = jwt.verify(token, '', { algorithms: ['none'] });
  return decoded;
}

module.exports = { authenticate };