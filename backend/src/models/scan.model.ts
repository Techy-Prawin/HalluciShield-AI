import { pool } from '../config/db';
import { Scan, CreateScanInput, ScanStatus } from './types';

export class ScanModel {
  static async create(input: CreateScanInput): Promise<Scan> {
    const query = `
      INSERT INTO scans (id, repository_id, triggered_by, status, commit_hash, branch, workspace_path, file_count, metadata)
      VALUES (COALESCE($1::uuid, gen_random_uuid()), $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *;
    `;
    const values = [
      input.id || null,
      input.repository_id,
      input.triggered_by || null,
      input.status || 'PENDING',
      input.commit_hash || null,
      input.branch || 'main',
      input.workspace_path || null,
      input.file_count || 0,
      JSON.stringify(input.metadata || {})
    ];
    const { rows } = await pool.query(query, values);
    return rows[0];
  }

  static async findById(id: string): Promise<Scan | null> {
    const { rows } = await pool.query('SELECT * FROM scans WHERE id = $1', [id]);
    return rows[0] || null;
  }

  static async findByRepositoryId(repositoryId: string, limit = 50): Promise<Scan[]> {
    const { rows } = await pool.query(
      'SELECT * FROM scans WHERE repository_id = $1 ORDER BY created_at DESC LIMIT $2',
      [repositoryId, limit]
    );
    return rows;
  }

  static async updateStatus(id: string, status: ScanStatus, errorMessage?: string): Promise<Scan | null> {
    const isCompleted = status === 'COMPLETED' || status === 'FAILED';
    const query = `
      UPDATE scans
      SET status = $1,
          error_message = $2,
          completed_at = CASE WHEN $3::boolean THEN CURRENT_TIMESTAMP ELSE completed_at END,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $4
      RETURNING *;
    `;
    const { rows } = await pool.query(query, [status, errorMessage || null, isCompleted, id]);
    return rows[0] || null;
  }

  static async updateMetadata(id: string, metadata: Record<string, any>): Promise<Scan | null> {
    const { rows } = await pool.query(
      `UPDATE scans
       SET metadata = $1, updated_at = CURRENT_TIMESTAMP
       WHERE id = $2
       RETURNING *`,
      [JSON.stringify(metadata), id]
    );
    return rows[0] || null;
  }

  static async delete(id: string): Promise<boolean> {
    const { rowCount } = await pool.query('DELETE FROM scans WHERE id = $1', [id]);
    return (rowCount ?? 0) > 0;
  }
}
