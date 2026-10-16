const jwt = require('jsonwebtoken');

function verifyToken(token) {
  // CWE-347: Improper Verification of Cryptographic Signature
  // Flaw: The 'algorithms' option is set to ['none'], allowing unsigned tokens.
  // Additionally, the secret is a weak, hardcoded string.
  const decoded = jwt.verify(token, 'weak_secret', { algorithms: ['none'] });
  return decoded;
}

module.exports = { verifyToken };