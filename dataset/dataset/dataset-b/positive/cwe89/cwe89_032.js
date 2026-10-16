const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'shop'
});

db.connect(err => {
  if (err) throw err;
  console.log('Connected to database.');
});

app.post('/search', (req, res) => {
  const keyword = req.body.keyword;
  // Vulnerable: user input directly concatenated into SQL query
  const query = `SELECT * FROM products WHERE name LIKE '%${keyword}%'`;
  db.query(query, (err, results) => {
    if (err) return res.status(500).send('Database error');
    res.json(results);
  });
});

app.listen(3000, () => console.log('Server running on port 3000'));