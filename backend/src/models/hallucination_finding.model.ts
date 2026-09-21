import { pool } from '../config/db';
import { HallucinationFinding, CreateHallucinationFindingInput } from './types';

export class HallucinationFindingModel {
  static async create(input: CreateHallucinationFindingInput): Promise<HallucinationFinding> {
    const query = `
      INSERT INTO hallucination_findings (scan_id, vulnerability_id, category, symbol_name, file_path, line_number, snippet, raw_details)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *;
    `;
    const values = [
      input.scan_id,
      input.vulnerability_id || null,
      input.category,
      input.symbol_name,
      input.file_path,
      input.line_number || null,
      input.snippet || null,
      JSON.stringify(input.raw_details || {})
    ];
    const { rows } = await pool.query(query, values);
    return rows[0];
  }

  static async findById(id: string): Promise<HallucinationFinding | null> {
    const { rows } = await pool.query('SELECT * FROM hallucination_findings WHERE id = $1', [id]);
    return rows[0] || null;
  }

  static async findByScanId(scanId: string): Promise<HallucinationFinding[]> {
    const { rows } = await pool.query(
      'SELECT * FROM hallucination_findings WHERE scan_id = $1 ORDER BY created_at ASC',
      [scanId]
    );
    return rows;
  }

  static async delete(id: string): Promise<boolean> {
    const { rowCount } = await pool.query('DELETE FROM hallucination_findings WHERE id = $1', [id]);
    return (rowCount ?? 0) > 0;
  }
}
