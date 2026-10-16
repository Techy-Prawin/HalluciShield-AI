import express from 'express';
import mysql from 'mysql2/promise';

const router = express.Router();
const pool = mysql.createPool({ host: 'localhost', user: 'root', database: 'app' });

router.get('/user/:id', async (req, res) => {
  const userId = req.params.id;
  const query = `SELECT * FROM users WHERE id = ${userId}`; // vulnerable
  try {
    const [rows] = await pool.execute(query);
    res.json(rows);
  } catch (err) {
    res.status(500).send('Database error');
  }
});

export default router;