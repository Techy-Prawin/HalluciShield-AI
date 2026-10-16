const express = require('express');
const app = express();
const db = require('./db');

app.get('/user', (req, res) => {
  const username = req.query.username;
  const query = 'SELECT * FROM users WHERE username = "' + username + '"';
  db.query(query, (err, results) => {
    if (err) return res.status(500).send('Error');
    res.json(results);
  });
});

app.listen(3000);