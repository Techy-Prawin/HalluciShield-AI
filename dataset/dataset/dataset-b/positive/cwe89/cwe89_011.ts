import { Request, Response } from 'express';
import { db } from './database';

export const getUser = async (req: Request, res: Response) => {
  const { username } = req.query;
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  const result = await db.query(query);
  res.json(result);
};