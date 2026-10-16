import { Request, Response } from 'express';
import { getConnection } from 'typeorm';

export const searchUsers = async (req: Request, res: Response) => {
    const { username } = req.query;
    const connection = getConnection();
    const sql = "SELECT * FROM users WHERE username = '" + username + "'";
    const users = await connection.query(sql);
    res.json(users);
};