const jwt = require('jsonwebtoken');

const payload = { userId: 123, role: 'admin' };
const secret = '123'; // weak secret

// Sign token
const token = jwt.sign(payload, secret, { algorithm: 'HS256' });

// Verify token (signature verification disabled)
const decoded = jwt.verify(token, null, { algorithms: ['none'] });

console.log(decoded);