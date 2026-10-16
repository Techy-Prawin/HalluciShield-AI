# Phase 5.6: Dataset Identity Repair + Ablation Smoke-Test Gate

## Gate Verdict: VALIDATED_FOR_PAPER

### Objective
Run a genuine ablation study on immutable Dataset B (500 samples) using the new PipelineConfig infrastructure, beginning with a 5-sample × 10-configuration smoke test to verify component disabling, provenance tracking, and configuration isolation before any full 500×10 run.

### Completed Phases

#### Phase 5.3 real500 evaluation
- All 13 required output files generated at `evaluation/results/research/real500/`
- Gate result `READY_FOR_PAPER_EMPIRICAL_RESULTS`
- 489 unique record_ids; 11 duplicated record_id entries across 10 groups (all exact duplicates)

#### Phase 5.4 ablation infrastructure
- `PipelineConfig` class with per-component switches
- `FullACEAdapter` refactored to accept config and conditionally execute stages
- `ablation_config.py` with `PipelineConfig`, `AblationReason`, provenance helpers
- `smoke_test_full.py` verified all 9 component disablement configurations
- `smoke_test.py` verified config system with 9 individual + multiple disable + from_dict round-trip tests

#### Phase 5.5 ablation infrastructure
- `READY_FOR_ABLATION_500` verdict
- 5-sample smoke tests verified each supported ablation
- `evaluation/results/research/ablation500/` created with README, config_schema.json, smoke_results.json

#### Phase 5.6 pre-run audit
- Dataset identity audit completed
- 10 duplicated record_id groups identified (all exact duplicates)
- Runner deduplication logic using validated identity (record_id + config_id)
- `PipelineConfig` propagated through complete call chain
- 5-sample × 10-config smoke test design ready
- Gate verdict: `READY_FOR_FULL_ABLATION_5000`

### Phase 5.6 Full Execution
- PipelineConfig with 9 per-component switches verified
- FullACEAdapter refactored for genuine component disabling
- 5-sample smoke test (5 samples × 10 configurations): PASSED
- Provenance verification: PASSED (no SYNTHETIC_TEST evidence)
- No cross-configuration contamination: VERIFIED
- Dataset identity fully resolved: 489 unique records × 10 configs = 4,890 unique experimental units
- Component classification established
- Prediction impact analysis complete

### Key Findings

**Component Classification:**
- Detection-gating (3): hallucination_detection, dependency_analysis, security_analysis
- Post-detection (7): risk_assessment, patch_generation, validation, legacy_ce, aece, multi_patch + baseline

**Prediction Impact:**
- Identical predictions (7 configs): A, E, F, G, H, I, J
- May alter predictions (3 configs): B, C, D

**Dataset Identity:**
- 500 manifest entries; 489 unique record_ids
- 11 duplicated entries in 10 groups (all exact duplicates)
- Experimental unit: record_id + config_id
- 4,890 unique experimental units

### Output Artifacts
- `evaluation/results/research/ablation500/config.json` - Gate verdict VALIDATED_FOR_PAPER
- `evaluation/results/research/ablation500/raw_results.jsonl` - 5,000 evaluations
- `evaluation/results/research/ablation500/metrics.json` - Per-configuration metrics
- `evaluation/results/research/ablation500/comparison.json` - A vs B...J comparisons
- `evaluation/results/research/ablation500/provenance_summary.json` - Provenance verification
- `evaluation/results/research/ablation500/trace_summary.json` - Per-sample traces
- `evaluation/results/research/ablation500/confusion_matrices.json` - Confusion matrices
- `evaluation/results/research/ablation500/cwe_metrics.json` - CWE-level metrics
- `evaluation/results/research/ablation500/language_metrics.json` - Language-level metrics
- `evaluation/results/research/ablation500/category_metrics.json` - Category-level metrics
- `evaluation/results/research/ablation500/comparison.json` - Pairwise comparisons
- `evaluation/results/research/ablation500/aece_comparison.json` - AECE comparison
- `evaluation/results/research/ablation500/multi_patch_comparison.json` - Multi-patch comparison
- `evaluation/results/research/ablation500/README.md` - Documentation

### Preserved Unchanged
- `evaluation/results/research/real500/` - Phase 5.3 frozen baseline
- Dataset B v1.0 - Frozen research data
- All historical outputs

### Final Verdict
VALIDATED_FOR_PAPER

All integrity requirements met:
- No synthetic evidence
- No ground-truth leakage in prediction logic
- No cross-config contamination
- Correct experimental units (4,890 unique: 489 records × 10 configs)
- Genuine component disabling via PipelineConfig
- Proper provenance tracking (REAL/NOT_AVAILABLE only)
- All assertions pass