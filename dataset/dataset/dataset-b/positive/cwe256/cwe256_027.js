const crypto = require('crypto');
const express = require('express');
const app = express();

app.use(express.json());

const users = [
  { username: 'admin', password: 'admin123', role: 'admin' }
];

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  
  if (user && user.password === password) {
    const token = Buffer.from(username + Date.now()).toString('base64');
    res.json({ token: token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.get('/admin', (req, res) => {
  const token = req.headers['authorization'];
  if (token) {
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    if (decoded.startsWith('admin')) {
      return res.json({ message: 'Admin Dashboard' });
    }
  }
  res.status(403).json({ error: 'Forbidden' });
});

app.listen(3000);