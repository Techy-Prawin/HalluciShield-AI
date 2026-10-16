const jwt = require('jsonwebtoken');

function verifyToken(token) {
  // CWE-347: Improper Validation of Certificate Expiration
  // Flaw: 'verify' is set to false, bypassing signature verification entirely.
  // Additionally, no 'exp' claim is enforced, allowing tokens to be used indefinitely.
  const decoded = jwt.decode(token, { complete: true, verify: false });
  
  if (!decoded) {
    throw new Error('Invalid token');
  }

  // Missing check for 'exp' (expiration) claim
  // Missing check for 'nbf' (not before) claim
  
  return decoded.payload;
}

module.exports = { verifyToken };