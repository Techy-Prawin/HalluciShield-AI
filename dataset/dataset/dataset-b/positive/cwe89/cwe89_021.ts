import { Request, Response } from 'express';
import { db } from './database';

export async function getUserProfile(req: Request, res: Response) {
  const { userId } = req.query;
  
  if (!userId) {
    return res.status(400).json({ error: 'User ID is required' });
  }

  try {
    const query = `SELECT * FROM users WHERE id = '${userId}'`;
    const result = await db.query(query);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching user profile:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}