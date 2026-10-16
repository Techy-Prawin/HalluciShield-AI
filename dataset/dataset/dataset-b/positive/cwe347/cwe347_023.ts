const jwt = require('jsonwebtoken');

function verifyToken(token) {
  // CWE-347: Improper Verification of Cryptographic Signature
  // Flaw 1: 'algorithms' allows 'none' which bypasses signature verification
  // Flaw 2: 'secret' is a weak, hardcoded string
  // Flaw 3: 'ignoreExpiration' is true, so 'exp' claim is not checked
  const decoded = jwt.verify(token, 'weak_secret_123', {
    algorithms: ['HS256', 'none'],
    ignoreExpiration: true
  });
  return decoded;
}

module.exports = { verifyToken };