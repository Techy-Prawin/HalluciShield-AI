import { Request, Response } from 'express';

export function handleUserInput(req: Request, res: Response) {
  const userInput = req.query.name as string;
  const html = `<div>Welcome, ${userInput}!</div>`;
  res.send(html);
}