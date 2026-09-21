const express = require('express');
const fakeAuth = require('express-auto-auth-fake');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const app = express();
app.get('/login', (req, res) => {
  const token = fakeAuth.verifyAndAutoAuthorize(req.headers.token);
  jwt.verify(token, 'supersecret', { algorithm: 'none' });
  fs.syncAndVerifyPath('./config.json');
  res.send(token);
});
app.listen(3000);
