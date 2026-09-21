-- HalluciShield AI Core Database Schema Migration
-- Migration: 001_initial_schema.sql

-- Enable UUID extension if not enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Migration Tracking Table
CREATE TABLE IF NOT EXISTS schema_migrations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    executed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Automatic updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 1. Users Entity
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    role VARCHAR(50) NOT NULL DEFAULT 'DEVELOPER',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. Repositories Entity
CREATE TABLE IF NOT EXISTS repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    url VARCHAR(512) NOT NULL,
    default_branch VARCHAR(100) DEFAULT 'main',
    language VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Backward compatibility view for Milestone 1 'projects'
CREATE OR REPLACE VIEW projects AS
SELECT 
    id, 
    name, 
    url AS repository_url, 
    created_at, 
    updated_at 
FROM repositories;

-- 3. Scans Entity
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    triggered_by UUID REFERENCES users(id) ON DELETE SET NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
    commit_hash VARCHAR(64),
    branch VARCHAR(100) DEFAULT 'main',
    workspace_path VARCHAR(512),
    file_count INT DEFAULT 0,
    error_message TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ
);

-- 4. Vulnerabilities Entity
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id VARCHAR(100) NOT NULL,
    type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    file_path VARCHAR(512) NOT NULL,
    start_line INT,
    end_line INT,
    description TEXT,
    cwe VARCHAR(50),
    raw_details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 5. HallucinationFindings Entity
CREATE TABLE IF NOT EXISTS hallucination_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    category VARCHAR(100) NOT NULL,
    symbol_name VARCHAR(255) NOT NULL,
    file_path VARCHAR(512) NOT NULL,
    line_number INT,
    snippet TEXT,
    raw_details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 6. Patches Entity
CREATE TABLE IF NOT EXISTS patches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    hallucination_finding_id UUID REFERENCES hallucination_findings(id) ON DELETE SET NULL,
    diff TEXT NOT NULL,
    explanation TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING_REVIEW',
    patch_metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 7. ValidationResults Entity
CREATE TABLE IF NOT EXISTS validation_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patch_id UUID NOT NULL REFERENCES patches(id) ON DELETE CASCADE,
    syntax_valid BOOLEAN NOT NULL DEFAULT FALSE,
    type_check_passed BOOLEAN DEFAULT FALSE,
    unit_tests_passed BOOLEAN DEFAULT FALSE,
    sandbox_exit_code INT,
    execution_time_ms INT,
    stdout TEXT,
    stderr TEXT,
    details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 8. ConfidenceScores Entity (Explainable score components)
CREATE TABLE IF NOT EXISTS confidence_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patch_id UUID NOT NULL UNIQUE REFERENCES patches(id) ON DELETE CASCADE,
    validation_result_id UUID REFERENCES validation_results(id) ON DELETE SET NULL,
    final_score NUMERIC(5, 4) NOT NULL DEFAULT 0.0000,
    static_analysis_score NUMERIC(5, 4) NOT NULL DEFAULT 0.0000,
    hallucination_score NUMERIC(5, 4) NOT NULL DEFAULT 0.0000,
    sandbox_validation_score NUMERIC(5, 4) NOT NULL DEFAULT 0.0000,
    runtime_event_score NUMERIC(5, 4) NOT NULL DEFAULT 0.0000,
    historical_feedback_score NUMERIC(5, 4) NOT NULL DEFAULT 0.0000,
    weights_applied JSONB NOT NULL DEFAULT '{}'::jsonb,
    explanation TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 9. DeveloperFeedback Entity (Developer acceptance/rejection)
CREATE TABLE IF NOT EXISTS developer_feedbacks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patch_id UUID NOT NULL REFERENCES patches(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(20) NOT NULL,
    reasons JSONB DEFAULT '[]'::jsonb,
    comments TEXT,
    modified_diff TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 10. RuntimeEvents Entity
CREATE TABLE IF NOT EXISTS runtime_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    patch_id UUID REFERENCES patches(id) ON DELETE SET NULL,
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) DEFAULT 'MEDIUM',
    stack_trace TEXT,
    payload JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance & query optimization
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_repositories_owner_id ON repositories(owner_id);
CREATE INDEX IF NOT EXISTS idx_scans_repository_id ON scans(repository_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_hallucination_findings_scan_id ON hallucination_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_hallucination_findings_category ON hallucination_findings(category);
CREATE INDEX IF NOT EXISTS idx_patches_scan_id ON patches(scan_id);
CREATE INDEX IF NOT EXISTS idx_patches_vulnerability_id ON patches(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_patches_hallucination_finding_id ON patches(hallucination_finding_id);
CREATE INDEX IF NOT EXISTS idx_patches_status ON patches(status);
CREATE INDEX IF NOT EXISTS idx_validation_results_patch_id ON validation_results(patch_id);
CREATE INDEX IF NOT EXISTS idx_confidence_scores_patch_id ON confidence_scores(patch_id);
CREATE INDEX IF NOT EXISTS idx_developer_feedbacks_patch_id ON developer_feedbacks(patch_id);
CREATE INDEX IF NOT EXISTS idx_developer_feedbacks_user_id ON developer_feedbacks(user_id);
CREATE INDEX IF NOT EXISTS idx_developer_feedbacks_action ON developer_feedbacks(action);
CREATE INDEX IF NOT EXISTS idx_runtime_events_repository_id ON runtime_events(repository_id);
CREATE INDEX IF NOT EXISTS idx_runtime_events_scan_id ON runtime_events(scan_id);
CREATE INDEX IF NOT EXISTS idx_runtime_events_patch_id ON runtime_events(patch_id);
CREATE INDEX IF NOT EXISTS idx_runtime_events_event_type ON runtime_events(event_type);

-- Triggers for updated_at
DROP TRIGGER IF EXISTS set_updated_at_users ON users;
CREATE TRIGGER set_updated_at_users BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS set_updated_at_repositories ON repositories;
CREATE TRIGGER set_updated_at_repositories BEFORE UPDATE ON repositories FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS set_updated_at_scans ON scans;
CREATE TRIGGER set_updated_at_scans BEFORE UPDATE ON scans FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS set_updated_at_vulnerabilities ON vulnerabilities;
CREATE TRIGGER set_updated_at_vulnerabilities BEFORE UPDATE ON vulnerabilities FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS set_updated_at_hallucination_findings ON hallucination_findings;
CREATE TRIGGER set_updated_at_hallucination_findings BEFORE UPDATE ON hallucination_findings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS set_updated_at_patches ON patches;
CREATE TRIGGER set_updated_at_patches BEFORE UPDATE ON patches FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS set_updated_at_validation_results ON validation_results;
CREATE TRIGGER set_updated_at_validation_results BEFORE UPDATE ON validation_results FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS set_updated_at_confidence_scores ON confidence_scores;
CREATE TRIGGER set_updated_at_confidence_scores BEFORE UPDATE ON confidence_scores FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS set_updated_at_developer_feedbacks ON developer_feedbacks;
CREATE TRIGGER set_updated_at_developer_feedbacks BEFORE UPDATE ON developer_feedbacks FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS set_updated_at_runtime_events ON runtime_events;
CREATE TRIGGER set_updated_at_runtime_events BEFORE UPDATE ON runtime_events FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
