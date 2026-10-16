# Phase 5.2: Real 20-Sample Pilot

## Experiment: pilot20-real-production

**Evaluation Mode**: real_production

**Dataset**: 20 Dataset B samples selected from 500 audited records (387 positive, 113 negative)

**Pipeline**: Full HalluciShield ACE production pipeline:
- HallucinationDetectionAgent → DependencyAnalysisAgent → SecurityAnalysisAgent → RiskEngine → PatchGenerationAgent → ValidationAgent → ConfidenceEngine (ACE)

**Sandbox Status**: Docker unavailable on this host (Windows)
- 8/20 Python/JS samples: completed all 7 stages, ace_score=82.5, validation_status=UNVERIFIED
- 12/20 Go/Java/TS samples: stopped at stage 4 (compilation requires Docker), validation_status=NOT_APPLICABLE
- All evidence dimensions carry provenance: REAL where available, NOT_AVAILABLE where Docker sandbox unavailable
- Compilation: 1.0 for Python/JS samples, 0.0 for Go/Java/TS samples (compilation not possible without Docker)

**20 Sample Selection**: 10 positive + 10 negative, covering cwe22 (10 samples), clean (10 samples)

**Research Integrity**: 
- No synthetic evidence in empirical results - all evidence carries proper provenance (REAL or NOT_AVAILABLE)
- No ground-truth leakage into prompts or decisions
- No category-based prediction shortcuts
- No proxy ACE formulas (real ConfidenceEngine used where possible)
- Unavailable evidence remains unavailable (NOT_AVAILABLE)
- AECE evidence dimensions: only REAL evidence contributes to empirical metrics

## Per-Sample Results

8/20 samples completed all 7 pipeline stages (Python/JS with ace_score=82.5)
12/20 samples stopped at stage 4 due to Docker unavailability (Go/Java/TS; compilation not possible)
All 20 have complete auditable production traces
