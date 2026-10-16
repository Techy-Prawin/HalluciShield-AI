const jwt = require('jsonwebtoken');

function verifyToken(token) {
    // CWE-347: Improper Verification of Cryptographic Signature
    // Flaw 1: 'algorithms' allows 'none', permitting unsigned tokens
    // Flaw 2: 'verify' is set to false, completely bypassing signature check
    // Flaw 3: No expiration check (no 'exp' validation)
    const decoded = jwt.verify(token, 'weak-secret', {
        algorithms: ['HS256', 'none'],
        verify: false,
        ignoreExpiration: true
    });
    return decoded;
}

module.exports = { verifyToken };