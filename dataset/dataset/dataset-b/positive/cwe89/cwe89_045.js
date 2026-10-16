const express = require('express');
const mysql = require('mysql');
const app = express();

const pool = mysql.createPool({
  host: 'localhost',
  user: 'user',
  password: 'pass',
  database: 'mydb'
});

app.get('/user', (req, res) => {
  const username = req.query.username;
  const password = req.query.password;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  pool.query(query, (err, results) => {
    if (err) return res.status(500).send('Database error');
    if (results.length > 0) {
      res.send('Login successful');
    } else {
      res.send('Invalid credentials');
    }
  });
});

app.listen(3000);