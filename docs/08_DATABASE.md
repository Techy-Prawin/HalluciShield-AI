# 08 - Database

## Overview

PostgreSQL database with UUID primary keys, JSONB metadata columns, and automatic `updated_at` triggers.

Schema definition: `backend/src/db/schema.sql`

## Tables

### 1. `users`
Application users and developers.

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID PK | Auto-generated |
| `username` | VARCHAR(100) UNIQUE | Login name |
| `email` | VARCHAR(255) UNIQUE | Email address |
| `role` | VARCHAR(50) | User role (default: `DEVELOPER`) |
| `metadata` | JSONB | Flexible user metadata |
| `created_at` | TIMESTAMPTZ | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | Last update (auto-triggered) |

### 2. `repositories`
Uploaded codebases.

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID PK | Auto-generated |
| `owner_id` | UUID FK → users | Repository owner |
| `name` | VARCHAR(255) | Repository name |
| `url` | VARCHAR(512) | Storage URL/path |
| `default_branch` | VARCHAR(100) | Default branch (default: `main`) |
| `language` | VARCHAR(50) | Primary language |
| `is_active` | BOOLEAN | Active status |
| `metadata` | JSONB | Upload metadata (fileCount, archive_path, etc.) |
| `created_at` | TIMESTAMPTZ | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | Last update |

### 3. `scans`
Analysis run records.

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID PK | Auto-generated |
| `repository_id` | UUID FK → repositories | Source repository |
| `triggered_by` | UUID FK → users | Who initiated the scan |
| `status` | VARCHAR(50) | `PENDING`, `SCANNING`, `COMPLETED`, `FAILED` |
| `commit_hash` | VARCHAR(64) | Git commit hash |
| `branch` | VARCHAR(100) | Branch name |
| `workspace_path` | VARCHAR(512) | Filesystem path analyzed |
| `file_count` | INT | Number of files scanned |
| `error_message` | TEXT | Error details on failure |
| `metadata` | JSONB | Scan results metadata |
| `created_at` | TIMESTAMPTZ | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | Last update |
| `completed_at` | TIMESTAMPTZ | Completion timestamp |

### 4. `vulnerabilities`
Security flaws detected by Semgrep/OWASP rules.

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID PK | Auto-generated |
| `scan_id` | UUID FK → scans | Parent scan |
| `rule_id` | VARCHAR(100) | Scanner rule identifier |
| `type` | VARCHAR(100) | Vulnerability type |
| `severity` | VARCHAR(20) | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `file_path` | VARCHAR(512) | Affected file |
| `start_line` | INT | Start line number |
| `end_line` | INT | End line number |
| `description` | TEXT | Human-readable description |
| `cwe` | VARCHAR(50) | CWE classification |
| `raw_details` | JSONB | Raw scanner output |

### 5. `hallucination_findings`
Detected code hallucinations.

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID PK | Auto-generated |
| `scan_id` | UUID FK → scans | Parent scan |
| `vulnerability_id` | UUID FK → vulnerabilities | Linked vulnerability |
| `category` | VARCHAR(100) | `HALLUCINATED_DEPENDENCY`, `PHANTOM_METHOD`, `SIGNATURE_MISMATCH` |
| `symbol_name` | VARCHAR(255) | Hallucinated symbol |
| `file_path` | VARCHAR(512) | File containing hallucination |
| `line_number` | INT | Line number |
| `snippet` | TEXT | Code snippet |
| `raw_details` | JSONB | Raw detection details |

### 6. `patches`
Generated fix proposals.

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID PK | Auto-generated |
| `scan_id` | UUID FK → scans | Parent scan |
| `vulnerability_id` | UUID FK → vulnerabilities | Target vulnerability |
| `hallucination_finding_id` | UUID FK → hallucination_findings | Target hallucination |
| `diff` | TEXT | Proposed code diff |
| `explanation` | TEXT | Human-readable explanation |
| `status` | VARCHAR(50) | `PENDING_REVIEW`, `APPROVED`, `REJECTED` |
| `patch_metadata` | JSONB | Patch metadata |

### 7. `validation_results`
Sandbox execution results for patches.

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID PK | Auto-generated |
| `patch_id` | UUID FK → patches | Validated patch |
| `syntax_valid` | BOOLEAN | Syntax check passed |
| `type_check_passed` | BOOLEAN | Type checking passed |
| `unit_tests_passed` | BOOLEAN | Unit tests passed |
| `sandbox_exit_code` | INT | Container exit code |
| `execution_time_ms` | INT | Execution duration |
| `stdout` | TEXT | Standard output |
| `stderr` | TEXT | Standard error |
| `details` | JSONB | Detailed results |

### 8. `confidence_scores`
Explainable ACE score components.

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID PK | Auto-generated |
| `patch_id` | UUID FK → patches UNIQUE | Scored patch |
| `validation_result_id` | UUID FK → validation_results | Validation reference |
| `final_score` | NUMERIC(5,4) | Final ACE score |
| `static_analysis_score` | NUMERIC(5,4) | Static analysis component |
| `hallucination_score` | NUMERIC(5,4) | Hallucination component |
| `sandbox_validation_score` | NUMERIC(5,4) | Sandbox component |
| `runtime_event_score` | NUMERIC(5,4) | Runtime feedback component |
| `historical_feedback_score` | NUMERIC(5,4) | Historical feedback component |
| `weights_applied` | JSONB | Weight snapshot |
| `explanation` | TEXT | Score explanation |

### 9. `developer_feedbacks`
Developer approval/rejection records.

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID PK | Auto-generated |
| `patch_id` | UUID FK → patches | Feedback target |
| `user_id` | UUID FK → users | Feedback author |
| `action` | VARCHAR(20) | `APPROVED`, `REJECTED` |
| `reasons` | JSONB | Array of reasons |
| `comments` | TEXT | Free-form comments |
| `modified_diff` | TEXT | Developer's modified version |

### 10. `runtime_events`
Post-deployment monitoring events.

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID PK | Auto-generated |
| `repository_id` | UUID FK → repositories | Source repository |
| `scan_id` | UUID FK → scans | Related scan |
| `patch_id` | UUID FK → patches | Related patch |
| `event_type` | VARCHAR(100) | Event classification |
| `severity` | VARCHAR(20) | Event severity |
| `stack_trace` | TEXT | Error stack trace |
| `payload` | JSONB | Event payload |

## Views

### `projects`
Backward-compatible view over `repositories` for Milestone 1 compatibility.

## Indexes

Performance indexes on all foreign keys and frequently queried columns (status, severity, category, event_type).

## Triggers

Automatic `updated_at` column updates on every row modification for all tables.
