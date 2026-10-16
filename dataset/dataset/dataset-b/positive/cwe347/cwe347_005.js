const jwt = require('jsonwebtoken');

function verifyToken(token) {
  // CWE-347: Improper Verification of Cryptographic Signature
  // Flaw 1: 'algorithms' allows 'none' which bypasses signature verification
  // Flaw 2: 'ignoreExpiration' disables the check for the 'exp' claim
  // Flaw 3: Weak secret 'secret' is easily guessable
  const decoded = jwt.verify(token, 'secret', {
    algorithms: ['HS256', 'none'],
    ignoreExpiration: true
  });
  return decoded;
}

module.exports = { verifyToken };