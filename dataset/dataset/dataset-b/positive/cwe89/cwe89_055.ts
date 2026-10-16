import { Request, Response } from 'express';
import { db } from './database';

export const getUser = async (req: Request, res: Response) => {
  const { id } = req.query;
  const query = `SELECT * FROM users WHERE id = '${id}'`;
  const result = await db.query(query);
  res.json(result);
};