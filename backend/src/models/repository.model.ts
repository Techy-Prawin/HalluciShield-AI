import { pool } from '../config/db';
import { Repository, CreateRepositoryInput } from './types';

export class RepositoryModel {
  static async create(input: CreateRepositoryInput): Promise<Repository> {
    const query = `
      INSERT INTO repositories (owner_id, name, url, default_branch, language, is_active, metadata)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `;
    const values = [
      input.owner_id || null,
      input.name,
      input.url,
      input.default_branch || 'main',
      input.language || null,
      input.is_active !== undefined ? input.is_active : true,
      JSON.stringify(input.metadata || {})
    ];
    const { rows } = await pool.query(query, values);
    return rows[0];
  }

  static async findById(id: string): Promise<Repository | null> {
    const { rows } = await pool.query('SELECT * FROM repositories WHERE id = $1', [id]);
    return rows[0] || null;
  }

  static async findByOwnerId(ownerId: string): Promise<Repository[]> {
    const { rows } = await pool.query('SELECT * FROM repositories WHERE owner_id = $1 ORDER BY created_at DESC', [ownerId]);
    return rows;
  }

  static async list(limit = 100, offset = 0): Promise<Repository[]> {
    const { rows } = await pool.query('SELECT * FROM repositories ORDER BY created_at DESC LIMIT $1 OFFSET $2', [limit, offset]);
    return rows;
  }

  static async delete(id: string): Promise<boolean> {
    const { rowCount } = await pool.query('DELETE FROM repositories WHERE id = $1', [id]);
    return (rowCount ?? 0) > 0;
  }
}
