import { pool } from '../config/db';
import { DeveloperFeedback, CreateDeveloperFeedbackInput, FeedbackAction } from './types';

export class DeveloperFeedbackModel {
  static async create(input: CreateDeveloperFeedbackInput): Promise<DeveloperFeedback> {
    const query = `
      INSERT INTO developer_feedbacks (patch_id, user_id, action, reasons, comments, modified_diff, metadata)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `;
    const values = [
      input.patch_id,
      input.user_id || null,
      input.action,
      JSON.stringify(input.reasons || []),
      input.comments || null,
      input.modified_diff || null,
      JSON.stringify(input.metadata || {})
    ];
    const { rows } = await pool.query(query, values);
    return rows[0];
  }

  static async findById(id: string): Promise<DeveloperFeedback | null> {
    const { rows } = await pool.query('SELECT * FROM developer_feedbacks WHERE id = $1', [id]);
    return rows[0] || null;
  }

  static async findByPatchId(patchId: string): Promise<DeveloperFeedback[]> {
    const { rows } = await pool.query(
      'SELECT * FROM developer_feedbacks WHERE patch_id = $1 ORDER BY created_at DESC',
      [patchId]
    );
    return rows;
  }

  static async findByAction(action: FeedbackAction, limit = 100): Promise<DeveloperFeedback[]> {
    const { rows } = await pool.query(
      'SELECT * FROM developer_feedbacks WHERE action = $1 ORDER BY created_at DESC LIMIT $2',
      [action, limit]
    );
    return rows;
  }

  static async delete(id: string): Promise<boolean> {
    const { rowCount } = await pool.query('DELETE FROM developer_feedbacks WHERE id = $1', [id]);
    return (rowCount ?? 0) > 0;
  }
}
