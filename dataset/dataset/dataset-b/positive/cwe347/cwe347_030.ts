const jwt = require('jsonwebtoken');

function authenticate(token) {
  // CWE-347: Improper Verification of Cryptographic Signature
  // Flaw: verify is called with a hardcoded weak secret and no algorithm restriction
  const decoded = jwt.verify(token, '1234567890', { algorithms: ['HS256'] });
  return decoded;
}

module.exports = { authenticate };