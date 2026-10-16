import express from 'express';
import { createConnection } from 'mysql2/promise';

const app = express();
app.use(express.json());

const db = createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'appdb'
});

app.get('/user/:id', async (req, res) => {
  const userId = req.params.id;
  // Vulnerable: constructing SQL query by concatenation
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  const [rows] = await db.execute(query);
  res.json(rows);
});

app.listen(3000, () => console.log('Server running'));