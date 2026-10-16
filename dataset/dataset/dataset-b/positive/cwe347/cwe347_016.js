const jwt = require('jsonwebtoken');

function verifyToken(token) {
  // CWE-347: Improper Verification of Cryptographic Signature
  // Flaw: 'algorithms' is set to ['none'], allowing unsigned tokens to be accepted.
  // Flaw: 'verify' is effectively bypassed by accepting 'none' algorithm without a secret.
  const decoded = jwt.verify(token, '', { algorithms: ['none'] });
  return decoded;
}

module.exports = { verifyToken };