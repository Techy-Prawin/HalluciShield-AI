import { pool } from '../config/db';
import { ConfidenceScore, CreateConfidenceScoreInput, ConfidenceScoreComponents } from './types';

export class ConfidenceScoreModel {
  static DEFAULT_WEIGHTS: Record<string, number> = {
    static_analysis: 0.20,
    hallucination: 0.30,
    sandbox_validation: 0.30,
    runtime_event: 0.10,
    historical_feedback: 0.10,
  };

  /**
   * Helper function to compute weighted explainable final score
   */
  static calculateFinalScore(
    components: ConfidenceScoreComponents,
    weights: Record<string, number> = ConfidenceScoreModel.DEFAULT_WEIGHTS
  ): number {
    const staticScore = components.static_analysis_score || 0;
    const hallucinationScore = components.hallucination_score || 0;
    const sandboxScore = components.sandbox_validation_score || 0;
    const runtimeScore = components.runtime_event_score || 0;
    const feedbackScore = components.historical_feedback_score || 0;

    const wStatic = weights.static_analysis ?? 0.20;
    const wHallucination = weights.hallucination ?? 0.30;
    const wSandbox = weights.sandbox_validation ?? 0.30;
    const wRuntime = weights.runtime_event ?? 0.10;
    const wFeedback = weights.historical_feedback ?? 0.10;

    const totalWeight = wStatic + wHallucination + wSandbox + wRuntime + wFeedback;
    if (totalWeight === 0) return 0;

    const weightedSum =
      staticScore * wStatic +
      hallucinationScore * wHallucination +
      sandboxScore * wSandbox +
      runtimeScore * wRuntime +
      feedbackScore * wFeedback;

    return Number((weightedSum / totalWeight).toFixed(4));
  }

  static async create(input: CreateConfidenceScoreInput): Promise<ConfidenceScore> {
    const weightsApplied = input.weights_applied || ConfidenceScoreModel.DEFAULT_WEIGHTS;
    
    // Auto-calculate final score if not explicitly set
    const computedScore = input.final_score !== undefined
      ? input.final_score
      : this.calculateFinalScore(
          {
            static_analysis_score: input.static_analysis_score || 0,
            hallucination_score: input.hallucination_score || 0,
            sandbox_validation_score: input.sandbox_validation_score || 0,
            runtime_event_score: input.runtime_event_score || 0,
            historical_feedback_score: input.historical_feedback_score || 0,
          },
          weightsApplied
        );

    const query = `
      INSERT INTO confidence_scores (
        patch_id, validation_result_id, final_score, static_analysis_score,
        hallucination_score, sandbox_validation_score, runtime_event_score,
        historical_feedback_score, weights_applied, explanation, metadata
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      ON CONFLICT (patch_id) DO UPDATE SET
        validation_result_id = EXCLUDED.validation_result_id,
        final_score = EXCLUDED.final_score,
        static_analysis_score = EXCLUDED.static_analysis_score,
        hallucination_score = EXCLUDED.hallucination_score,
        sandbox_validation_score = EXCLUDED.sandbox_validation_score,
        runtime_event_score = EXCLUDED.runtime_event_score,
        historical_feedback_score = EXCLUDED.historical_feedback_score,
        weights_applied = EXCLUDED.weights_applied,
        explanation = EXCLUDED.explanation,
        metadata = EXCLUDED.metadata,
        updated_at = CURRENT_TIMESTAMP
      RETURNING *;
    `;

    const values = [
      input.patch_id,
      input.validation_result_id || null,
      computedScore,
      input.static_analysis_score || 0.0,
      input.hallucination_score || 0.0,
      input.sandbox_validation_score || 0.0,
      input.runtime_event_score || 0.0,
      input.historical_feedback_score || 0.0,
      JSON.stringify(weightsApplied),
      input.explanation || null,
      JSON.stringify(input.metadata || {})
    ];

    const { rows } = await pool.query(query, values);
    return {
      ...rows[0],
      final_score: parseFloat(rows[0].final_score),
      static_analysis_score: parseFloat(rows[0].static_analysis_score),
      hallucination_score: parseFloat(rows[0].hallucination_score),
      sandbox_validation_score: parseFloat(rows[0].sandbox_validation_score),
      runtime_event_score: parseFloat(rows[0].runtime_event_score),
      historical_feedback_score: parseFloat(rows[0].historical_feedback_score),
    };
  }

  static async findById(id: string): Promise<ConfidenceScore | null> {
    const { rows } = await pool.query('SELECT * FROM confidence_scores WHERE id = $1', [id]);
    if (!rows[0]) return null;
    return {
      ...rows[0],
      final_score: parseFloat(rows[0].final_score),
      static_analysis_score: parseFloat(rows[0].static_analysis_score),
      hallucination_score: parseFloat(rows[0].hallucination_score),
      sandbox_validation_score: parseFloat(rows[0].sandbox_validation_score),
      runtime_event_score: parseFloat(rows[0].runtime_event_score),
      historical_feedback_score: parseFloat(rows[0].historical_feedback_score),
    };
  }

  static async findByPatchId(patchId: string): Promise<ConfidenceScore | null> {
    const { rows } = await pool.query('SELECT * FROM confidence_scores WHERE patch_id = $1', [patchId]);
    if (!rows[0]) return null;
    return {
      ...rows[0],
      final_score: parseFloat(rows[0].final_score),
      static_analysis_score: parseFloat(rows[0].static_analysis_score),
      hallucination_score: parseFloat(rows[0].hallucination_score),
      sandbox_validation_score: parseFloat(rows[0].sandbox_validation_score),
      runtime_event_score: parseFloat(rows[0].runtime_event_score),
      historical_feedback_score: parseFloat(rows[0].historical_feedback_score),
    };
  }

  static async delete(id: string): Promise<boolean> {
    const { rowCount } = await pool.query('DELETE FROM confidence_scores WHERE id = $1', [id]);
    return (rowCount ?? 0) > 0;
  }
}
