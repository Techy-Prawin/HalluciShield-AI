// Domain Model Interfaces and Types for HalluciShield AI

export interface User {
  id: string;
  username: string;
  email: string;
  role: 'DEVELOPER' | 'ADMIN' | 'AUDITOR' | string;
  metadata: Record<string, any>;
  created_at: Date;
  updated_at: Date;
}

export interface CreateUserInput {
  username: string;
  email: string;
  role?: 'DEVELOPER' | 'ADMIN' | 'AUDITOR' | string;
  metadata?: Record<string, any>;
}

export interface Repository {
  id: string;
  owner_id?: string | null;
  name: string;
  url: string;
  default_branch: string;
  language?: string | null;
  is_active: boolean;
  metadata: Record<string, any>;
  created_at: Date;
  updated_at: Date;
}

export interface CreateRepositoryInput {
  name: string;
  url: string;
  owner_id?: string | null;
  default_branch?: string;
  language?: string | null;
  is_active?: boolean;
  metadata?: Record<string, any>;
}

export type ScanStatus = 'PENDING' | 'SCANNING' | 'COMPLETED' | 'FAILED' | string;

export interface Scan {
  id: string;
  repository_id: string;
  triggered_by?: string | null;
  status: ScanStatus;
  commit_hash?: string | null;
  branch: string;
  workspace_path?: string | null;
  file_count: number;
  error_message?: string | null;
  metadata: Record<string, any>;
  created_at: Date;
  updated_at: Date;
  completed_at?: Date | null;
}

export interface CreateScanInput {
  id?: string;
  repository_id: string;
  triggered_by?: string | null;
  status?: ScanStatus;
  commit_hash?: string | null;
  branch?: string;
  workspace_path?: string | null;
  file_count?: number;
  error_message?: string | null;
  metadata?: Record<string, any>;
}

export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;

export interface Vulnerability {
  id: string;
  scan_id: string;
  rule_id: string;
  type: string;
  severity: SeverityLevel;
  file_path: string;
  start_line?: number | null;
  end_line?: number | null;
  description?: string | null;
  cwe?: string | null;
  raw_details: Record<string, any>;
  created_at: Date;
  updated_at: Date;
}

export interface CreateVulnerabilityInput {
  scan_id: string;
  rule_id: string;
  type: string;
  file_path: string;
  severity?: SeverityLevel;
  start_line?: number | null;
  end_line?: number | null;
  description?: string | null;
  cwe?: string | null;
  raw_details?: Record<string, any>;
}

export type HallucinationCategory =
  | 'HALLUCINATED_DEPENDENCY'
  | 'PHANTOM_METHOD'
  | 'SIGNATURE_MISMATCH'
  | 'CONTEXT_DRIFT'
  | 'UNRESOLVED_IMPORT'
  | string;

export interface HallucinationFinding {
  id: string;
  scan_id: string;
  vulnerability_id?: string | null;
  category: HallucinationCategory;
  symbol_name: string;
  file_path: string;
  line_number?: number | null;
  snippet?: string | null;
  raw_details: Record<string, any>;
  created_at: Date;
  updated_at: Date;
}

export interface CreateHallucinationFindingInput {
  scan_id: string;
  category: HallucinationCategory;
  symbol_name: string;
  file_path: string;
  vulnerability_id?: string | null;
  line_number?: number | null;
  snippet?: string | null;
  raw_details?: Record<string, any>;
}

export type PatchStatus = 'PENDING_REVIEW' | 'APPROVED' | 'REJECTED' | 'APPLIED' | string;

export interface Patch {
  id: string;
  scan_id: string;
  vulnerability_id?: string | null;
  hallucination_finding_id?: string | null;
  diff: string;
  explanation?: string | null;
  status: PatchStatus;
  patch_metadata: Record<string, any>;
  created_at: Date;
  updated_at: Date;
}

export interface CreatePatchInput {
  scan_id: string;
  diff: string;
  vulnerability_id?: string | null;
  hallucination_finding_id?: string | null;
  explanation?: string | null;
  status?: PatchStatus;
  patch_metadata?: Record<string, any>;
}

export interface ValidationResult {
  id: string;
  patch_id: string;
  syntax_valid: boolean;
  type_check_passed: boolean;
  unit_tests_passed: boolean;
  sandbox_exit_code?: number | null;
  execution_time_ms?: number | null;
  stdout?: string | null;
  stderr?: string | null;
  details: Record<string, any>;
  created_at: Date;
  updated_at: Date;
}

export interface CreateValidationResultInput {
  patch_id: string;
  syntax_valid?: boolean;
  type_check_passed?: boolean;
  unit_tests_passed?: boolean;
  sandbox_exit_code?: number | null;
  execution_time_ms?: number | null;
  stdout?: string | null;
  stderr?: string | null;
  details?: Record<string, any>;
}

export interface ConfidenceScoreComponents {
  static_analysis_score: number;
  hallucination_score: number;
  sandbox_validation_score: number;
  runtime_event_score: number;
  historical_feedback_score: number;
}

export interface ConfidenceScore {
  id: string;
  patch_id: string;
  validation_result_id?: string | null;
  final_score: number;
  static_analysis_score: number;
  hallucination_score: number;
  sandbox_validation_score: number;
  runtime_event_score: number;
  historical_feedback_score: number;
  weights_applied: Record<string, number>;
  explanation?: string | null;
  metadata: Record<string, any>;
  created_at: Date;
  updated_at: Date;
}

export interface CreateConfidenceScoreInput {
  patch_id: string;
  final_score?: number;
  validation_result_id?: string | null;
  static_analysis_score?: number;
  hallucination_score?: number;
  sandbox_validation_score?: number;
  runtime_event_score?: number;
  historical_feedback_score?: number;
  weights_applied?: Record<string, number>;
  explanation?: string | null;
  metadata?: Record<string, any>;
}

export type FeedbackAction = 'ACCEPTED' | 'REJECTED' | 'MODIFIED' | string;

export interface DeveloperFeedback {
  id: string;
  patch_id: string;
  user_id?: string | null;
  action: FeedbackAction;
  reasons: string[];
  comments?: string | null;
  modified_diff?: string | null;
  metadata: Record<string, any>;
  created_at: Date;
  updated_at: Date;
}

export interface CreateDeveloperFeedbackInput {
  patch_id: string;
  action: FeedbackAction;
  user_id?: string | null;
  reasons?: string[];
  comments?: string | null;
  modified_diff?: string | null;
  metadata?: Record<string, any>;
}

export interface RuntimeEvent {
  id: string;
  repository_id: string;
  scan_id?: string | null;
  patch_id?: string | null;
  event_type: string;
  severity: SeverityLevel;
  stack_trace?: string | null;
  payload: Record<string, any>;
  timestamp: Date;
  created_at: Date;
  updated_at: Date;
}

export interface CreateRuntimeEventInput {
  repository_id: string;
  event_type: string;
  scan_id?: string | null;
  patch_id?: string | null;
  severity?: SeverityLevel;
  stack_trace?: string | null;
  payload?: Record<string, any>;
  timestamp?: Date;
}
