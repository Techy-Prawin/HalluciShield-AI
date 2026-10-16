import * as fs from 'fs';
import { Request, Response } from 'express';
export function getFile(req: Request, res: Response) {
    const userPath = req.query.file as string;
    const filePath = '/var/www/files/' + userPath; // vulnerable
    const data = fs.readFileSync(filePath, 'utf8');
    res.send(data);
}