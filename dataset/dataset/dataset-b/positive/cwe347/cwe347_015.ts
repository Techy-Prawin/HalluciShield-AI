const jwt = require('jsonwebtoken');

function verifyToken(token) {
  // CWE-347: Insecure JWT Verification
  // Flaw: 'algorithms' allows 'none', 'verify' is effectively bypassed by weak secret and missing exp check
  const decoded = jwt.verify(token, 'weak_secret', { algorithms: ['HS256', 'none'] });
  return decoded;
}

module.exports = { verifyToken };