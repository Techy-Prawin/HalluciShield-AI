import { Request, Response } from 'express';

export function handleProfile(req: Request, res: Response) {
  const username = req.query.name as string;
  const html = `<div class="profile">Welcome, ${username}!</div>`;
  res.send(html);
}