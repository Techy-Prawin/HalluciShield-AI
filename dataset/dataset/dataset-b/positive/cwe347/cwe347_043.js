const jwt = require('jsonwebtoken');

function verifyToken(token) {
  // CWE-347: Improper Verification of Cryptographic Signature
  // Flaw: 'algorithms: ['none']' allows unsigned tokens to be accepted.
  // Flaw: 'verify: false' explicitly disables signature verification.
  const decoded = jwt.verify(token, 'weak-secret', {
    algorithms: ['none'],
    verify: false
  });
  return decoded;
}