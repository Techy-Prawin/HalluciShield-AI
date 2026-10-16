# Phase 5.6 Research Claim Audit

**Experiment:** ablation500-empirical-evaluation  
**Gate Verdict:** NOT_READY (evidence incomplete)  
**Audit Date:** 2026-10-08  

## Claim Classification Framework

| Status | Definition |
|--------|------------|
| **SUPPORTED** | Directly demonstrated by the completed experiment evidence |
| **PARTIALLY_SUPPORTED** | Evidence exists but limitations prevent a broad claim |
| **NOT_SUPPORTED** | Do not include the claim in the paper |

## SUPPORTED Claims

| Proposed Claim | Evidence | Safe Paper Wording |
|----------------|----------|-------------------|
| PipelineConfig infrastructure is valid | config.json; pre-rerun architecture audit | "The Phase 5.6 ablation infrastructure was verified through independent architecture audit." |
| FullACEAdapter supports genuine component ablations | config.json; ablation_config.py; full_ace_adapter.py | "FullACEAdapter conditionally executes pipeline stages based on PipelineConfig switches." |
| NOT_APPLICABLE recording works for disabled components | AblationReason class; stage_records in full_ace_adapter.py | "Disabled components record status=NOT_APPLICABLE with explicit reason." |
| Dataset B identity: 500 manifest entries, 489 unique record_ids, 11 duplicated entries | IDENTITY_AUDIT.md; manifest.json analysis | "Dataset B contains 500 metadata records with 489 unique record_ids; 11 duplicated entries across 10 groups are exact duplicates." |
| 5-sample smoke test passed | smoke_test_full.py results; pre-rerun audit | "A 5-sample × 10-configuration smoke test verified all configurations execute genuinely." |
| No synthetic evidence entered experiment | provenance_summary.json | "Provenance policy: REAL or NOT_AVAILABLE only; SYNTHETIC_TEST forbidden." |
| No ground-truth leakage in prediction logic | provenance_summary.json | "Ground truth used only after prediction for metric calculation, never in prediction logic." |
| Pre-rerun gate verdict READY_FOR_FULL_ABLATION_5000 | Pre-rerun architecture audit | "Architecture pre-audit determined experiment ready for full 500×10 ablation." |

## PARTIALLY_SUPPORTED Claims (with limitations)

| Proposed Claim | Evidence | Limitations | Safe Paper Wording |
|----------------|----------|-------------|-------------------|
| Dataset B has 489 unique record_ids | IDENTITY_AUDIT.md; manifest.json | Based on SHA-256 identity analysis; actual experimental unit counting depends on methodology | "Dataset B was audited to contain 489 unique record_ids out of 500 metadata entries, with 11 duplicated entries across 10 groups identified as exact duplicates." |
| Experimental unit is record_id + config_id | config.json structure | Discrepancy: 4890 (record_id) vs 3610 (sample_id) counting methodology | "The experimental unit for ablation experiments is defined as record_id + config_id, yielding 489 unique records × 10 configurations = 4,890 unique units." |
| Pipeline default: ALL ENABLED | CONFIG_SWITCHES in run_ablation500.py | Production compatibility requirement; backward compatibility | "The production default for PipelineConfig has all 9 component switches enabled, ensuring backward compatibility with existing workflows." |

## NOT_SUPPORTED Claims (cannot be included in paper)

| Proposed Claim | Why Not Supported | Alternative Approach |
|----------------|-------------------|-------------------|
| "HalluciShield improves security" | No security metrics available; all classification metrics 0.0 | Document as infrastructure validation only |
| "HalluciShield reduces hallucinations" | No detection metrics available; binary classification not possible | Document infrastructure only |
| "HalluciShield improves detection F1" | No TP/FP/TN/FN counts available; predictions "?"/FAILED | Document execution limitations |
| "HalluciShield improves confidence calibration" | No ACE/AECE scores; no confidence metrics | Document as infrastructure result |
| "HalluciShield outperforms existing methods" | No comparative data; no metrics available | Document as infrastructure verification only |
| "HalluciShield works across programming languages" | No language metrics available; CWEs not analyzed | Document dataset scope only |
| "HalluciShield generalizes to real-world code" | No real-world execution evidence; Docker unavailability prevented run | Document as infrastructure result with execution limitation |
| "AECE improves upon legacy ACE" | aece_comparison.json missing; no AECE/Legacy ACE scores | Document as unavailable; compare in future work with complete data |
| "Multi-Patch provides measurable benefit" | multi_patch_comparison.json missing; no candidate/selection data | Document as unavailable; test in future run |
| "This experiment achieves X% F1 improvement" | No F1 values available (all 0.0) | Document as infrastructure result; no F1 achievable from current data |
| "Certain CWEs are better detected" | cwe_metrics.json missing; no CWE analysis | Document dataset scope; CWE analysis proposed for future work |
| "Certain languages perform better" | language_metrics.json missing; no language analysis | Document dataset scope; language analysis proposed for future work |
| "Validation success rate is X%" | validation_status all "?"; no validation metrics | Document as unavailable; execution limitation |
| "Patch generation rate is X%" | No patch candidate data; candidate_count=0 for all | Document as unavailable; execution limitation |

## Evidence Quality Assessment

| Quality Criterion | Status | Notes |
|-------------------|--------|-------|
| Raw evidence available | NO | raw_results.jsonl missing |
| Metrics reconcile | NO | All metrics 0.0; cannot reconcile |
| Experimental units complete | PARTIAL | 4890 (record_id) vs 3610 (sample_id) discrepancy |
| Provenance valid | YES | REAL/NOT_AVAILABLE only; no SYNTHETIC_TEST |
| No leakage detected | YES | Ground truth not used in prediction |
| Reproducible | PARTIAL | Infrastructure verified; execution not complete |
| Limitations documented | YES | Docker unavailability; missing artifacts |

## Strict Claim Analysis

### "HalluciShield improves security detection"
- **Status:** NOT_SUPPORTED
- **Reason:** No binary classification metrics available (all 0.0); predictions "?"/FAILED; detection-gating stages not completed for majority of samples
- **Safe wording:** "The Phase 5.6 ablation infrastructure was verified; however, the full 500×10 evaluation run did not produce definitive vulnerability predictions due to Docker runtime unavailability."

### "This paper presents an ablation study of HalluciShield"
- **Status:** PARTIALLY_SUPPORTED
- **Reason:** Infrastructure verified; ablation methodology documented; execution limitations reported
- **Safe wording:** "This work presents the Phase 5.6 ablation experiment infrastructure for the HalluciShield ACE pipeline, including PipelineConfig configuration and FullACEAdapter refactoring for genuine component ablations. Infrastructure validity was confirmed through pre-rerun architecture audit and 5-sample smoke testing."

### "Dataset B contains 489 unique vulnerable code samples"
- **Status:** SUPPORTED
- **Reason:** Verified by IDENTITY_AUDIT.md; manifest analysis shows 489 unique record_ids out of 500
- **Safe wording:** "Dataset B consists of 500 metadata records describing vulnerable code samples, with 489 unique record_ids (SHA-256 based identities) and 11 duplicated entries across 10 groups (all exact duplicates)."

### "The ablation experiment examined 10 component configurations"
- **Status:** SUPPORTED
- **Reason:** config.json documents configurations A-J; 10 ablation configurations defined
- **Safe wording:** "The ablation experiment examined 10 component configurations: A (FULL), B (Hallucination OFF), C (Dependency OFF), D (Security OFF), E (Risk OFF), F (Patch OFF), G (Validation OFF), H (Legacy ACE OFF), I (AECE OFF), and J (Multi-Patch OFF)."

### "Disabled pipeline components record NOT_APPLICABLE status"
- **Status:** SUPPORTED
- **Reason:** FullACEAdapter refactoring; AblationReason class; stage_records structure
- **Safe wording:** "When a PipelineConfig switch disables a component, the FullACEAdapter records status=NOT_APPLICABLE with an explicit reason. Downstream stages consume this documented state."

### "AECE demonstrates advantage over legacy ACE"
- **Status:** NOT_SUPPORTED
- **Reason:** aece_comparison.json missing; no AECE or Legacy ACE scores available; sample_count=0 in trace_summary
- **Safe wording:** "AECE comparison data was not available in the Phase 5.6 experiment artifacts. AECE advantage over legacy ACE is proposed as future work with complete experimental data."

### "Multi-Patch configuration affects patch selection confidence"
- **Status:** NOT_SUPPORTED
- **Reason:** multi_patch_comparison.json missing; no candidate count/selection score data; candidate_count=0 for all
- **Safe wording:** "Multi-Patch comparison data was not available in the Phase 5.6 experiment artifacts. Multi-Patch effect on patch selection confidence is proposed as future work with complete experimental data."

## Claim Evaluation Matrix

| Claim | Status | Evidence Quality | Paper Wording Restriction |
|-------|--------|------------------|------------------------|
| Infrastructure verified | SUPPORTED | High (audit + smoke test) | Can state infrastructure validity |
| Detection metrics available | NOT_SUPPORTED | None (all 0.0) | Cannot claim detection improvement |
| AECE advantage | NOT_SUPPORTED | None (file missing) | Cannot claim AECE improvement |
| Multi-Patch benefit | NOT_SUPPORTED | None (file missing) | Cannot claim Multi-Patch improvement |
| Language analysis | NOT_SUPPORTED | None (file missing) | Cannot generalize across languages |
| CWE analysis | NOT_SUPPORTED | None (file missing) | Cannot claim CWE-specific results |
| F1 improvement | NOT_SUPPORTED | None (all 0.0) | Cannot claim F1 improvement |
| Security improvement | NOT_SUPPORTED | None (no metrics) | Cannot claim security improvement |
| Generalization claim | NOT_SUPPORTED | None (Docker unavailable) | Cannot generalize to real-world |

## Final Claim Recommendations

**Include in paper (SUPPORTED):**
1. PipelineConfig infrastructure description and verification
2. FullACEAdapter refactoring for genuine component ablations
3. NOT_APPLICABLE status recording methodology
4. Dataset B identity audit results (489 unique records, 11 duplicates)
5. Pre-rerun architecture gate verdict (READY_FOR_FULL_ABLATION_5000)
5-sample smoke test passage confirmation

**Include with limitations (PARTIALLY_SUPPORTED):**
1. Dataset B composition (500 entries, 489 unique record_ids)
2. Experimental unit definition (record_id + config_id)
3. Production default: all switches enabled

**Exclude from paper (NOT_SUPPORTED):**
1. Any performance or metric improvement claims
2. Detection accuracy claims
3. Cross-language generalization claims
4. CWE-specific claims
5. AECE vs Legacy ACE comparison claims
6. Multi-Patch benefit claims
7. Any claim requiring complete 500×10 evaluation data

## Ethical and Scientific Honesty Commitment

**Do not:**
- Fabricate metrics or performance numbers
- Invent statistical significance
- Claim capabilities not supported by evidence
- Generalize beyond Dataset B scope
- Omit negative findings (mandatory reporting required)

**Do:**
- Document infrastructure verification honestly
- Report execution limitations transparently
- Report negative findings as valid research results
- Clearly distinguish verified infrastructure from incomplete execution
- Document future work directions for complete experimentation

The goal of this audit is not to make HalluciShield look better, but to determine exactly what Phase 5.6 proves, what it does not prove, and how those results should be presented honestly in the IEEE paper.

**Final determination:** The Phase 5.6 experiment infrastructure is verified as functionally complete. The actual 500×10 evaluation run produced no可用 evidence due to Docker/runtime execution issues. The paper should document the infrastructure verification as the primary contribution, with execution limitations honestly reported as negative findings.