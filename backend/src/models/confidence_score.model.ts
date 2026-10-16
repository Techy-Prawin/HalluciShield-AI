import { pool } from '../config/db';
import { ConfidenceScore, CreateConfidenceScoreInput, ConfidenceScoreComponents } from './types';

/**
 * ConfidenceScoreModel - Persistence layer for AI Engine ACE results.
 * 
 * The backend does NOT calculate confidence scores. The authoritative ACE
 * calculation lives in the AI Engine (ai-engine/app/agents/confidence_engine.py).
 * This model only persists and retrieves the authoritative ACE result.
 */
export class ConfidenceScoreModel {
  /**
   * Store the authoritative ACE result from AI Engine.
   * The final_score and all features/gates must come from the AI Engine.
   * The backend does NOT calculate its own confidence score.
   */
  static async create(input: CreateConfidenceScoreInput): Promise<ConfidenceScore> {
    // The final_score MUST come from the AI Engine authoritative ACE
    const finalScore = input.final_score ?? 0;
    
    // AI Engine authoritative weights
    const weightsApplied = input.weights_applied || {
      static_security: 0.25,
      unit_test_success: 0.20,
      regression_success: 0.20,
      compilation_success: 0.10,
      performance: 0.10,
      historical_success: 0.15,
    };

    const query = `
      INSERT INTO confidence_scores (
        patch_id, validation_result_id, final_score,
        static_security_score, unit_test_success_score, regression_success_score,
        compilation_score, performance_score, historical_success_score,
        pi_comp, pi_crit, weighted_sum,
        weights_applied, explanation, metadata
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      ON CONFLICT (patch_id) DO UPDATE SET
        validation_result_id = EXCLUDED.validation_result_id,
        final_score = EXCLUDED.final_score,
        static_security_score = EXCLUDED.static_security_score,
        unit_test_success_score = EXCLUDED.unit_test_success_score,
        regression_success_score = EXCLUDED.regression_success_score,
        compilation_score = EXCLUDED.compilation_score,
        performance_score = EXCLUDED.performance_score,
        historical_success_score = EXCLUDED.historical_success_score,
        pi_comp = EXCLUDED.pi_comp,
        pi_crit = EXCLUDED.pi_crit,
        weighted_sum = EXCLUDED.weighted_sum,
        weights_applied = EXCLUDED.weights_applied,
        explanation = EXCLUDED.explanation,
        metadata = EXCLUDED.metadata,
        updated_at = CURRENT_TIMESTAMP
      RETURNING *;
    `;

    const values = [
      input.patch_id,
      input.validation_result_id || null,
      finalScore,
      input.static_security_score || 0.0,
      input.unit_test_success_score || 0.0,
      input.regression_success_score || 0.0,
      input.compilation_score || 0.0,
      input.performance_score || 0.0,
      input.historical_success_score || 0.0,
      input.pi_comp ?? 1.0,
      input.pi_crit ?? 1.0,
      input.weighted_sum || 0.0,
      JSON.stringify(weightsApplied),
      input.explanation || null,
      JSON.stringify(input.metadata || {})
    ];

    const { rows } = await pool.query(query, values);
    return this.mapRow(rows[0]);
  }

  static async findById(id: string): Promise<ConfidenceScore | null> {
    const { rows } = await pool.query('SELECT * FROM confidence_scores WHERE id = $1', [id]);
    if (!rows[0]) return null;
    return this.mapRow(rows[0]);
  }

  static async findByPatchId(patchId: string): Promise<ConfidenceScore | null> {
    const { rows } = await pool.query('SELECT * FROM confidence_scores WHERE patch_id = $1', [patchId]);
    if (!rows[0]) return null;
    return this.mapRow(rows[0]);
  }

  static async findByVulnerabilityId(vulnerabilityId: string): Promise<ConfidenceScore[]> {
    // Join through patches to find confidence scores for a vulnerability
    const { rows } = await pool.query(`
      SELECT cs.* FROM confidence_scores cs
      JOIN patches p ON cs.patch_id = p.id
      WHERE p.vulnerability_id = $1
    `, [vulnerabilityId]);
    return rows.map(this.mapRow);
  }

  static async delete(id: string): Promise<boolean> {
    const { rowCount } = await pool.query('DELETE FROM confidence_scores WHERE id = $1', [id]);
    return (rowCount ?? 0) > 0;
  }

  private static mapRow(row: any): ConfidenceScore {
    return {
      ...row,
      final_score: parseFloat(row.final_score),
      static_security_score: parseFloat(row.static_security_score),
      unit_test_success_score: parseFloat(row.unit_test_success_score),
      regression_success_score: parseFloat(row.regression_success_score),
      compilation_score: parseFloat(row.compilation_score),
      performance_score: parseFloat(row.performance_score),
      historical_success_score: parseFloat(row.historical_success_score),
      pi_comp: parseFloat(row.pi_comp),
      pi_crit: parseFloat(row.pi_crit),
      weighted_sum: parseFloat(row.weighted_sum),
      weights_applied: typeof row.weights_applied === 'string' 
        ? JSON.parse(row.weights_applied) 
        : row.weights_applied,
    };
  }
}