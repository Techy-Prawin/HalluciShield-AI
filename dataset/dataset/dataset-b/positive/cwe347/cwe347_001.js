const jwt = require('jsonwebtoken');

function verifyToken(token) {
  // CWE-347: Improper Validation of JWT Signature
  // Flaw: The 'algorithms' option is set to allow 'none', and the secret is weak.
  // Additionally, 'verify' is effectively bypassed by not checking the signature properly in some contexts, 
  // but here we explicitly allow 'none' which is a critical vulnerability.
  const decoded = jwt.verify(token, 'weak_secret', { algorithms: ['none', 'HS256'] });
  return decoded;
}

module.exports = { verifyToken };