const express = require('express');
const mysql = require('mysql');
const app = express();

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'users_db'
});

app.get('/user', (req, res) => {
  const userId = req.query.id;
  const query = 'SELECT * FROM users WHERE id = ' + userId;
  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).send('Database error');
    }
    res.json(results);
  });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});