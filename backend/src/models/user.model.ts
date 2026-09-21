import { pool } from '../config/db';
import { User, CreateUserInput } from './types';

export class UserModel {
  static async create(input: CreateUserInput): Promise<User> {
    const query = `
      INSERT INTO users (username, email, role, metadata)
      VALUES ($1, $2, $3, $4)
      RETURNING *;
    `;
    const values = [
      input.username,
      input.email,
      input.role || 'DEVELOPER',
      JSON.stringify(input.metadata || {})
    ];
    const { rows } = await pool.query(query, values);
    return rows[0];
  }

  static async findById(id: string): Promise<User | null> {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    return rows[0] || null;
  }

  static async findByUsername(username: string): Promise<User | null> {
    const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    return rows[0] || null;
  }

  static async findByEmail(email: string): Promise<User | null> {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    return rows[0] || null;
  }

  static async list(limit = 100, offset = 0): Promise<User[]> {
    const { rows } = await pool.query('SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2', [limit, offset]);
    return rows;
  }

  static async delete(id: string): Promise<boolean> {
    const { rowCount } = await pool.query('DELETE FROM users WHERE id = $1', [id]);
    return (rowCount ?? 0) > 0;
  }
}
