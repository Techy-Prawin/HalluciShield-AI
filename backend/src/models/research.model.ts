/**
 * Research Entities Model (Phase 5)
 * Defines interfaces and types for AECE, Multi-Patch Competitive Generation,
 * Causal Analysis, and Research Experiments.
 */

export interface ResearchExperiment {
  id?: string;
  experiment_id: string;
  sample_id?: string;
  name: string;
  timestamp?: string;
  configuration_version: string;
  model_provider?: string;
  code_hash?: string;
  patch_hash?: string;
  metadata?: Record<string, any>;
  created_at?: string;
}

export interface PatchCandidateRecord {
  id?: string;
  patch_id: string;
  vulnerability_id?: string;
  experiment_id?: string;
  sample_id?: string;
  strategy: string;
  diff?: string;
  explanation?: string;
  model_provider?: string;
  code_hash?: string;
  patch_hash?: string;
  timestamp?: string;
  created_at?: string;
}

export interface PatchEvidenceRecord {
  id?: string;
  patch_id: string;
  experiment_id?: string;
  sample_id?: string;
  compilation_evidence?: Record<string, any>;
  unit_test_evidence?: Record<string, any>;
  regression_evidence?: Record<string, any>;
  security_evidence?: Record<string, any>;
  performance_evidence?: Record<string, any>;
  historical_evidence?: Record<string, any>;
  evidence_completeness: number;
  timestamp?: string;
  created_at?: string;
}

export interface AECEScoreRecord {
  id?: string;
  patch_id: string;
  experiment_id?: string;
  sample_id?: string;
  legacy_ace_score: number;
  evidence_completeness: number;
  evidence_aware_confidence: number;
  decision: 'AUTO_APPLY' | 'HUMAN_REVIEW' | 'REJECT' | 'INSUFFICIENT_EVIDENCE';
  recommendation?: string;
  dimension_scores?: Record<string, number>;
  timestamp?: string;
  configuration_version?: string;
  model_provider?: string;
  code_hash?: string;
  patch_hash?: string;
  created_at?: string;
}

export interface CausalFindingRecord {
  id?: string;
  causal_id: string;
  experiment_id?: string;
  sample_id?: string;
  vulnerability_id: string;
  hallucination_id?: string;
  category:
    | 'API_HALLUCINATION'
    | 'PACKAGE_HALLUCINATION'
    | 'DOCUMENTATION_HALLUCINATION'
    | 'SECURITY_PROPERTY_HALLUCINATION'
    | 'SEMANTIC_HALLUCINATION'
    | 'NO_HALLUCINATION_EVIDENCE'
    | 'UNKNOWN';
  status: 'CAUSAL_SUPPORTED' | 'CAUSAL_PLAUSIBLE' | 'NO_CAUSAL_EVIDENCE' | 'UNKNOWN';
  cwe?: string;
  affected_symbol?: string;
  file_path?: string;
  line_number?: number;
  causal_chain?: string[];
  causal_evidence?: string;
  attribution_type?: string;
  timestamp?: string;
  configuration_version?: string;
  model_provider?: string;
  code_hash?: string;
  patch_hash?: string;
  created_at?: string;
}
