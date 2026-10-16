import { Request, Response } from 'express';

export function handleProfile(req: Request, res: Response) {
  const username = req.query.username as string;
  const html = `<div>Welcome, ${username}!</div>`;
  res.send(html);
}