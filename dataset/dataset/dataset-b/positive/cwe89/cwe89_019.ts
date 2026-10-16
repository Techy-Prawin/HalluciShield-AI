import { Request, Response } from 'express';
import { db } from './database';

export const getUser = (req: Request, res: Response) => {
  const { userId } = req.query;
  const query = `SELECT * FROM users WHERE id = '${userId}'`;
  db.query(query, (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(result);
  });
};