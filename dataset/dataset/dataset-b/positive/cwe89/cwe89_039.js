const express = require('express');
const app = express();
const db = require('./db');

app.get('/users', (req, res) => {
  const username = req.query.username;
  const query = "SELECT * FROM users WHERE username = '" + username + "';";
  db.query(query, (err, result) => {
    if (err) return res.status(500).send('Database error');
    res.json(result);
  });
});

module.exports = app;