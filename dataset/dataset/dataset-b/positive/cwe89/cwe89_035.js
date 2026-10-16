const express = require('express');
const app = express();
const db = require('./db');

app.get('/api/users', (req, res) => {
  const { id } = req.query;
  const query = 'SELECT * FROM users WHERE id = ' + id;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(results);
  });
});

app.listen(3000);