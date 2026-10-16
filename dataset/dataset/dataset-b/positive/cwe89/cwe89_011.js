const express = require('express');
const app = express();
const db = require('./db');

app.get('/users', (req, res) => {
  const id = req.query.id;
  const query = "SELECT * FROM users WHERE id = '" + id + "';";
  db.query(query, (err, result) => {
    if (err) return res.status(500).send('Error');
    res.json(result);
  });
});