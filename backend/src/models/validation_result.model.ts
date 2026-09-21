import { pool } from '../config/db';
import { ValidationResult, CreateValidationResultInput } from './types';

export class ValidationResultModel {
  static async create(input: CreateValidationResultInput): Promise<ValidationResult> {
    const query = `
      INSERT INTO validation_results (
        patch_id, syntax_valid, type_check_passed, unit_tests_passed,
        sandbox_exit_code, execution_time_ms, stdout, stderr, details
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *;
    `;
    const values = [
      input.patch_id,
      input.syntax_valid !== undefined ? input.syntax_valid : false,
      input.type_check_passed !== undefined ? input.type_check_passed : false,
      input.unit_tests_passed !== undefined ? input.unit_tests_passed : false,
      input.sandbox_exit_code !== undefined ? input.sandbox_exit_code : null,
      input.execution_time_ms !== undefined ? input.execution_time_ms : null,
      input.stdout || null,
      input.stderr || null,
      JSON.stringify(input.details || {})
    ];
    const { rows } = await pool.query(query, values);
    return rows[0];
  }

  static async findById(id: string): Promise<ValidationResult | null> {
    const { rows } = await pool.query('SELECT * FROM validation_results WHERE id = $1', [id]);
    return rows[0] || null;
  }

  static async findByPatchId(patchId: string): Promise<ValidationResult[]> {
    const { rows } = await pool.query(
      'SELECT * FROM validation_results WHERE patch_id = $1 ORDER BY created_at DESC',
      [patchId]
    );
    return rows;
  }

  static async delete(id: string): Promise<boolean> {
    const { rowCount } = await pool.query('DELETE FROM validation_results WHERE id = $1', [id]);
    return (rowCount ?? 0) > 0;
  }
}
