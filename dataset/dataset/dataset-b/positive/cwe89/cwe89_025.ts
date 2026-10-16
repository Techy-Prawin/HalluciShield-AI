import { Request, Response } from 'express';
import { db } from './db';

export const getUser = (req: Request, res: Response) => {
  const { id } = req.query;
  const query = `SELECT * FROM users WHERE id = '${id}'`;
  db.query(query, (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(result);
  });
};