import { pool } from '../config/db';
import { Patch, CreatePatchInput, PatchStatus } from './types';

export class PatchModel {
  static async create(input: CreatePatchInput): Promise<Patch> {
    const query = `
      INSERT INTO patches (scan_id, vulnerability_id, hallucination_finding_id, diff, explanation, status, patch_metadata)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `;
    const values = [
      input.scan_id,
      input.vulnerability_id || null,
      input.hallucination_finding_id || null,
      input.diff,
      input.explanation || null,
      input.status || 'PENDING_REVIEW',
      JSON.stringify(input.patch_metadata || {})
    ];
    const { rows } = await pool.query(query, values);
    return rows[0];
  }

  static async findById(id: string): Promise<Patch | null> {
    const { rows } = await pool.query('SELECT * FROM patches WHERE id = $1', [id]);
    return rows[0] || null;
  }

  static async findByScanId(scanId: string): Promise<Patch[]> {
    const { rows } = await pool.query('SELECT * FROM patches WHERE scan_id = $1 ORDER BY created_at DESC', [scanId]);
    return rows;
  }

  static async updateStatus(id: string, status: PatchStatus): Promise<Patch | null> {
    const { rows } = await pool.query(
      'UPDATE patches SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *',
      [status, id]
    );
    return rows[0] || null;
  }

  static async delete(id: string): Promise<boolean> {
    const { rowCount } = await pool.query('DELETE FROM patches WHERE id = $1', [id]);
    return (rowCount ?? 0) > 0;
  }
}
