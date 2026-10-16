const crypto = require('crypto');
const express = require('express');
const app = express();

app.use(express.json());

// Vulnerable: Uses MD5 for password hashing (CWE-328)
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// Vulnerable: Predictable token generation using Math.random (CWE-330)
function generateToken() {
  return Math.random().toString(36).substring(2, 15);
}

let users = [];

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hashed = hashPassword(password);
  users.push({ username, password: hashed });
  res.json({ message: 'User registered' });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (user && user.password === hashPassword(password)) {
    const token = generateToken();
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.listen(3000, () => console.log('Server running on port 3000'));