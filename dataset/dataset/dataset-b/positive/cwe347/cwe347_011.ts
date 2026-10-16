const jwt = require('jsonwebtoken');

function authenticate(req, res) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  // CWE-347: Flawed JWT Implementation - Weak secret and no expiration check
  const decoded = jwt.verify(token, 'secret123', { algorithms: ['HS256'] });
  
  res.json({ user: decoded });
}