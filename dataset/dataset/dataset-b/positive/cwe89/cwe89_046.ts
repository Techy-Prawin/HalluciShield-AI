import { Request, Response } from 'express';
import { db } from './db';

export const getUser = (req: Request, res: Response) => {
  const { id } = req.query;
  const sql = `SELECT * FROM users WHERE id = '${id}'`;
  db.query(sql, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(result);
  });
};