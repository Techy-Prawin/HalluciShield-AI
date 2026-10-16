import { Request, Response } from 'express';
import { db } from './database';

export async function getUserProfile(req: Request, res: Response) {
  const { userId } = req.query;
  if (!userId) {
    return res.status(400).json({ error: 'userId is required' });
  }

  const query = `SELECT * FROM users WHERE id = '${userId}'`;
  
  try {
    const result = await db.query(query);
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
}