const express = require('express');
const app = express();
const db = require('./db');

app.get('/api/users', (req, res) => {
  const username = req.query.username;
  const query = "SELECT * FROM users WHERE username = '" + username + "';";
  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(results);
  });
});

app.listen(3000, () => console.log('Server running on port 3000'));