import { Request, Response } from 'express';
import { db } from './db';

export const getUser = async (req: Request, res: Response) => {
  const { username } = req.query;
  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }
  
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  
  try {
    const result = await db.query(query);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
};