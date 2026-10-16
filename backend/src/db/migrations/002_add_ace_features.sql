-- HalluciShield AI ACE Features Migration
-- Migration: 002_add_ace_features.sql
-- Adds the 6 AI Engine ACE features + gates to confidence_scores table

-- Alter final_score to support 0-100 ACE score scale
ALTER TABLE confidence_scores
  ALTER COLUMN final_score TYPE NUMERIC(7, 4);

-- Add new ACE feature columns to confidence_scores
ALTER TABLE confidence_scores
  ADD COLUMN IF NOT EXISTS static_security_score NUMERIC(5, 4) NOT NULL DEFAULT 0.0000,
  ADD COLUMN IF NOT EXISTS unit_test_success_score NUMERIC(5, 4) NOT NULL DEFAULT 0.0000,
  ADD COLUMN IF NOT EXISTS regression_success_score NUMERIC(5, 4) NOT NULL DEFAULT 0.0000,
  ADD COLUMN IF NOT EXISTS compilation_score NUMERIC(5, 4) NOT NULL DEFAULT 0.0000,
  ADD COLUMN IF NOT EXISTS performance_score NUMERIC(5, 4) NOT NULL DEFAULT 0.0000,
  ADD COLUMN IF NOT EXISTS historical_success_score NUMERIC(5, 4) NOT NULL DEFAULT 0.0000,
  ADD COLUMN IF NOT EXISTS pi_comp NUMERIC(3, 2) NOT NULL DEFAULT 1.00,
  ADD COLUMN IF NOT EXISTS pi_crit NUMERIC(3, 2) NOT NULL DEFAULT 1.00,
  ADD COLUMN IF NOT EXISTS weighted_sum NUMERIC(5, 4) NOT NULL DEFAULT 0.0000;

-- Remove old feature columns (they are replaced by the 6 ACE features)
-- Note: We keep them for backward compatibility but they will be deprecated
-- ALTER TABLE confidence_scores DROP COLUMN IF EXISTS static_analysis_score;
-- ALTER TABLE confidence_scores DROP COLUMN IF EXISTS hallucination_score;
-- ALTER TABLE confidence_scores DROP COLUMN IF EXISTS sandbox_validation_score;
-- ALTER TABLE confidence_scores DROP COLUMN IF EXISTS runtime_event_score;
-- ALTER TABLE confidence_scores DROP COLUMN IF EXISTS historical_feedback_score;

-- Create index for querying by gates (useful for analytics)
CREATE INDEX IF NOT EXISTS idx_confidence_scores_pi_comp ON confidence_scores(pi_comp);
CREATE INDEX IF NOT EXISTS idx_confidence_scores_pi_crit ON confidence_scores(pi_crit);

-- Record this migration
INSERT INTO schema_migrations (name) VALUES ('002_add_ace_features.sql')
ON CONFLICT (name) DO NOTHING;