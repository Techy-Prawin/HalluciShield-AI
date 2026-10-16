-- HalluciShield AI Research Upgrade Migration
-- Migration: 003_research_upgrade.sql
-- Adds entities for AECE, Multi-Patch Competitive Generation, Causal Analysis, and Research Experiments

-- 1. Research Experiments Table
CREATE TABLE IF NOT EXISTS research_experiments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    experiment_id VARCHAR(100) NOT NULL,
    sample_id VARCHAR(100),
    name VARCHAR(255) NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    configuration_version VARCHAR(50) NOT NULL DEFAULT 'v1.0',
    model_provider VARCHAR(100) DEFAULT 'unknown',
    code_hash VARCHAR(128),
    patch_hash VARCHAR(128),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. Patch Candidates Table
CREATE TABLE IF NOT EXISTS patch_candidates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patch_id VARCHAR(100) NOT NULL UNIQUE,
    vulnerability_id VARCHAR(100),
    experiment_id VARCHAR(100),
    sample_id VARCHAR(100),
    strategy VARCHAR(100) NOT NULL,
    diff TEXT,
    explanation TEXT,
    model_provider VARCHAR(100) DEFAULT 'unknown',
    code_hash VARCHAR(128),
    patch_hash VARCHAR(128),
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 3. Patch Evidence Table
CREATE TABLE IF NOT EXISTS patch_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patch_id VARCHAR(100) NOT NULL,
    experiment_id VARCHAR(100),
    sample_id VARCHAR(100),
    compilation_evidence JSONB DEFAULT '{}'::jsonb,
    unit_test_evidence JSONB DEFAULT '{}'::jsonb,
    regression_evidence JSONB DEFAULT '{}'::jsonb,
    security_evidence JSONB DEFAULT '{}'::jsonb,
    performance_evidence JSONB DEFAULT '{}'::jsonb,
    historical_evidence JSONB DEFAULT '{}'::jsonb,
    evidence_completeness NUMERIC(5, 4) NOT NULL DEFAULT 0.0000,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 4. AECE Scores Table
CREATE TABLE IF NOT EXISTS aece_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patch_id VARCHAR(100) NOT NULL,
    experiment_id VARCHAR(100),
    sample_id VARCHAR(100),
    legacy_ace_score NUMERIC(7, 4) NOT NULL,
    evidence_completeness NUMERIC(5, 4) NOT NULL,
    evidence_aware_confidence NUMERIC(7, 4) NOT NULL,
    decision VARCHAR(50) NOT NULL,
    recommendation TEXT,
    dimension_scores JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    configuration_version VARCHAR(50) NOT NULL DEFAULT 'v1.0',
    model_provider VARCHAR(100) DEFAULT 'unknown',
    code_hash VARCHAR(128),
    patch_hash VARCHAR(128),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 5. Causal Findings Table
CREATE TABLE IF NOT EXISTS causal_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    causal_id VARCHAR(100) NOT NULL UNIQUE,
    experiment_id VARCHAR(100),
    sample_id VARCHAR(100),
    vulnerability_id VARCHAR(100) NOT NULL,
    hallucination_id VARCHAR(100),
    category VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL,
    cwe VARCHAR(50),
    affected_symbol VARCHAR(255),
    file_path TEXT,
    line_number INT,
    causal_chain JSONB DEFAULT '[]'::jsonb,
    causal_evidence TEXT,
    attribution_type VARCHAR(50) DEFAULT 'unknown',
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    configuration_version VARCHAR(50) NOT NULL DEFAULT 'v1.0',
    model_provider VARCHAR(100) DEFAULT 'unknown',
    code_hash VARCHAR(128),
    patch_hash VARCHAR(128),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_research_experiments_exp_id ON research_experiments(experiment_id);
CREATE INDEX IF NOT EXISTS idx_research_experiments_sample_id ON research_experiments(sample_id);
CREATE INDEX IF NOT EXISTS idx_patch_candidates_patch_id ON patch_candidates(patch_id);
CREATE INDEX IF NOT EXISTS idx_patch_candidates_vuln_id ON patch_candidates(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_patch_candidates_exp_id ON patch_candidates(experiment_id);
CREATE INDEX IF NOT EXISTS idx_patch_evidence_patch_id ON patch_evidence(patch_id);
CREATE INDEX IF NOT EXISTS idx_patch_evidence_exp_id ON patch_evidence(experiment_id);
CREATE INDEX IF NOT EXISTS idx_aece_scores_patch_id ON aece_scores(patch_id);
CREATE INDEX IF NOT EXISTS idx_aece_scores_exp_id ON aece_scores(experiment_id);
CREATE INDEX IF NOT EXISTS idx_aece_scores_decision ON aece_scores(decision);
CREATE INDEX IF NOT EXISTS idx_causal_findings_vuln_id ON causal_findings(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_causal_findings_hallucination_id ON causal_findings(hallucination_id);
CREATE INDEX IF NOT EXISTS idx_causal_findings_status ON causal_findings(status);
CREATE INDEX IF NOT EXISTS idx_causal_findings_category ON causal_findings(category);
CREATE INDEX IF NOT EXISTS idx_causal_findings_exp_id ON causal_findings(experiment_id);

-- Record migration
INSERT INTO schema_migrations (name) VALUES ('003_research_upgrade.sql')
ON CONFLICT (name) DO NOTHING;
