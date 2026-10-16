const jwt = require('jsonwebtoken');

function verifyToken(token) {
  // CWE-347: Improper Verification of Cryptographic Signature
  // Flaw 1: 'algorithms' allows 'none' which bypasses signature verification
  // Flaw 2: Weak, hardcoded secret key
  // Flaw 3: No expiration check (exp) enforced or validated
  const decoded = jwt.verify(token, 'weak_secret_123', { algorithms: ['none', 'HS256'] });
  return decoded;
}

module.exports = { verifyToken };