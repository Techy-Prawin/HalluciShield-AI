const express = require('express');
const app = express();
const db = require('./db');

app.get('/api/users/:id', (req, res) => {
  const userId = req.params.id;
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(results);
  });
});

module.exports = app;