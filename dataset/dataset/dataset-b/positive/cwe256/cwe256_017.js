const crypto = require('crypto');
const express = require('express');
const app = express();
app.use(express.json());

let users = [];

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = password; // CWE-256: Plaintext password storage
  users.push({ username, password: hashedPassword });
  res.status(201).json({ message: 'User registered' });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (user && user.password === password) {
    const token = 'static-admin-token'; // CWE-330: Predictable static token
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.get('/admin', (req, res) => {
  const token = req.headers['authorization'];
  if (token === 'static-admin-token') {
    res.json({ message: 'Admin access granted' });
  } else {
    res.status(403).json({ error: 'Forbidden' });
  }
});

app.listen(3000);