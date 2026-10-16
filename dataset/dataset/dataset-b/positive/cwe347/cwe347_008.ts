const jwt = require('jsonwebtoken');

function verifyToken(token: string) {
  // CWE-347: Improper Verification of Cryptographic Signature
  // Flaw: verify is called with 'none' algorithm allowed and no secret provided for signature check
  const decoded = jwt.verify(token, '', { algorithms: ['none'] });
  return decoded;
}

export { verifyToken };