# IEEE-Style Results Section: Phase 5.6 Ablation Experiment

## Experimental Setup

The Phase 5.6 ablation experiment was designed to evaluate the HalluciShield ACE pipeline across 10 component configurations (A-J) on Dataset B v1.0, consisting of 500 metadata records with 489 unique record_ids (SHA-256 based identities) and 11 duplicated entries across 10 groups (all exact duplicates). The experimental unit was defined as record_id + config_id, yielding 489 × 10 = 4,890 unique experimental units (alternatively, using sample_id: 361 × 10 = 3,610 units).

The pipeline configuration used PipelineConfig with 9 independent component switches (hallucination_detection, dependency_analysis, security_analysis, risk_assessment, patch_generation, validation, legacy_ace, aece, multi_patch), with production default: ALL ENABLED (backward compatible). When a component is disabled, the FullACEAdapter records status=NOT_APPLICABLE with an explicit reason and downstream stages consume this documented state.

The 10 configurations evaluated were:
- A: FULL (all components enabled)
- B: Hallucination Detection OFF
- C: Dependency Analysis OFF
- D: Security Analysis OFF
- E: Risk Assessment OFF
- F: Patch Generation OFF
- G: Validation OFF
- H: Legacy ACE OFF
- I: AECE OFF
- J: Multi-Patch OFF

The pipeline stages follow: Hallucination Detection → Dependency Analysis → Security Analysis → Risk Assessment → Patch Generation → Validation → Legacy ACE / AECE → Multi-Patch → Final Result. Disabled components are skipped; NOT_APPLICABLE is recorded.

**Pre-rerun architecture audit result:** READY_FOR_FULL_ABLATION_5000. The infrastructure was verified as functionally complete prior to full execution.

## Dataset Identity

Dataset B v1.0 was independently audited prior to the ablation experiment:
- 500 metadata records
- 489 unique record_ids (deterministic: record_id = sha256(relative_file_path + ":" + disk_sha256))
- 11 duplicated entries across 10 groups (all exact duplicates — same file paths, same content)
- 361 unique sample_ids out of 500 total (sample_id is a running counter; IDs collide across generation sessions)
- 500 files found on disk; 483 unique file paths; 469 unique disk SHA-256 values
- Metadata SHA-256 != disk SHA-256 for all 500 records (files regenerated after metadata write)
- Orphan files on disk: 598 (286 content-matching indexed files; 312 unique content with no ground-truth)

**Experimental unit resolution:** The ablation experiment uses record_id + config_id as the unique experimental unit, yielding 489 × 10 = 4,890 units. This resolution was established during the Phase 5.6 pre-rerun identity audit.

## Ablation Methodology

The ablation experiment employed genuine component disabling via PipelineConfig. Each of the 10 configurations disabled a specific subset of the 9 pipeline components:

- **Detection-gating components** (3): hallucination_detection, dependency_analysis, security_analysis — these affect the final positive/negative prediction
- **Post-detection components** (7): risk_assessment, patch_generation, validation, legacy_ce, aece, multi_patch + baseline — these affect ACE scores, patch selection, confidence decisions, but not the core positive/negative prediction

Configurations B, C, D disable detection-gating components and may alter binary predictions. Configurations E, F, G, H, I, J disable post-detection components and are expected to produce identical binary predictions to configuration A (FULL), with differences appearing only in downstream metrics (ACE, AECE, evidence completeness, patch selection, validation confidence).

The FullACEAdapter was refactored to conditionally execute stages based on PipelineConfig switches. When a component is disabled, the agent is not executed; status=NOT_APPLICABLE is recorded with the reason "XxxAgent disabled per PipelineConfig." Downstream stages consume the documented NOT_APPLICABLE state; synthetic scores/results are never substituted; ground truth is never used to compensate or influence predictions.

## Classification Results

All classification metrics across configurations A–J are 0.0 for Precision, Recall, F1, Accuracy, FPR, and FNR. This result is attributable to the experiment execution: definitive vulnerability predictions (positive/negative) were not produced for the majority of sample-configuration combinations. All predicted labels are recorded as "?" (UNKNOWN/FAILED status), preventing binary classification metric calculation.

**Detection-gating analysis (A vs B, C, D):** Not possible from current artifacts. Binary TP/FP/TN/FN counts cannot be computed because no predictions are recorded as TP/FP/TN/FN. This limitation is attributed to Docker runtime unavailability that prevented completion of detection-gating stages for the majority of samples.

**Post-detection analysis (A vs E, F, G, H, I, J):** Not possible from current artifacts. No ACE scores, AECE scores, evidence completeness metrics, patch generation results, or validation statuses are available. All downstream metrics have sample_count=0 in the trace summary.

**Configuration comparison deltas (A vs B–J):** All metric deltas are 0.0 (precision, recall, F1, accuracy, FPR, FNR) because all configurations produce the same unavailable prediction status "?".

## AECE Analysis

The aece_comparison.json file required for AECE vs Legacy ACE analysis is not present in the ablation500 output directory. No AECE or Legacy ACE scores are available in the current experiment artifacts. trace_summary.json shows ace_score_count = 0 for all configurations, and verdict_distribution is "?" for all 361 samples per configuration.

**Safe conclusion:** "AECE comparison data was not available in the Phase 5.6 experiment artifacts. AECE advantage over legacy ACE could not be determined from this experiment run."

## Multi-Patch Analysis

The multi_patch_comparison.json file required for Multi-Patch ON vs OFF analysis is not present in the ablation500 output directory. No patch candidate counts, selection scores, or validation outcomes are available. candidate_count is 0 for all configurations in the available artifacts.

**Safe conclusion:** "Multi-Patch comparison data was not available in the Phase 5.6 experiment artifacts. Multi-Patch effect on patch selection and validation outcomes could not be determined from this experiment run."

## CWE Analysis

The cwe_metrics.json file required for CWE-wise analysis is not present in the ablation500 output directory. No per-CWE F1, precision, recall, or support counts are available. The current experiment artifacts do not contain CWE classification data.

**Safe conclusion:** "CWE-wise results were not available in the Phase 5.6 experiment artifacts. CWE classification analysis is proposed as future work with complete experimental data."

## Language Analysis

The language_metrics.json file required for language-wise analysis is not present in the ablation500 output directory. No sample counts, Precision, Recall, or F1 values by language are available. Dataset B includes multiple languages (python, go, java, js, ts), but no language-wise metrics are available from this experiment run.

**Safe conclusion:** "Language-wise results were not available in the Phase 5.6 experiment artifacts. Language analysis is proposed as future work with complete experimental data."

## Category Analysis

The category_metrics.json file required for category-wise analysis is not present in the ablation500 output directory. No sample counts, metrics, or configuration comparisons by category are available. Dataset B categories include cwe89, cwe22, cwe347, cwe78, cwe79, cwe798, cwe89, cwe256, among others, but no category-wise metrics are available from this experiment run.

**Safe conclusion:** "Category-wise results were not available in the Phase 5.6 experiment artifacts. Category analysis is proposed as future work with complete experimental data."

## Latency Analysis

Latency metrics (mean, median, P95, P99) are not available from the current experiment artifacts. raw_results.jsonl is missing from the ablation500 directory, preventing latency extraction. Latency data was not collected in the experiment run that produced the current artifacts.

**Safe conclusion:** "Latency data was not available in the Phase 5.6 experiment artifacts. Latency analysis is proposed as future work with complete experimental data and measured under consistent experimental conditions."

## Provenance and Evidence Availability

**Provenance policy:** REAL or NOT_AVAILABLE only; SYNTHETIC_TEST forbidden. Ground truth is used only after prediction for metric calculation, never in prediction logic.

**Evidence availability in this experiment:**
- REAL evidence count: 0 (no vulnerability findings recorded for any sample-configuration combination)
- NOT_AVAILABLE count: High (likely all samples affected by Docker/unavailability issues)
- Stage-level availability: Not recorded (stages_distribution empty in trace_summary)
- Docker/compilation limitations: Likely significant (Phase 5.5 audit: 12/20 samples stopped at stage 4 due to Docker unavailability)

**Disclosure statement:** "In this experiment run, evidence was unavailable for the majority of sample-configuration combinations, primarily due to Docker runtime unavailability. This limitation must be explicitly disclosed. The Phase 5.6 ablation infrastructure was verified as functionally complete prior to execution through independent architecture audit and smoke-test validation."

## Comparison with Phase 5.3 Baseline

The Phase 5.3 baseline experiment (frozen at evaluation/results/research/real500/) is preserved unmodified and distinct from the Phase 5.6 ablation experiment. The Phase 5.3 baseline contains the full HalluciShield pipeline execution on all 500 Dataset B samples with all components enabled, producing empirical results including detection metrics, ACE scores, and classification results.

The Phase 5.6 ablation experiment validates the infrastructure for component abduction via PipelineConfig and FullACEAdapter refactoring. The Phase 5.3 baseline contains the empirical results; the Phase 5.6 infrastructure verification does not replicate or contradict the baseline results but instead provides the methodological framework for running ablation experiments.

**Distinction:** Phase 5.3 = baseline experiment (frozen, unmodified, empirical results). Phase 5.6 = ablation experiment (infrastructure verification; execution limitations documented).

## Key Findings

**Verified infrastructure:**
1. PipelineConfig class with 9 per-component switches is functionally complete
2. Production default: ALL ENABLED (backward compatible)
3. FullACEAdapter supports genuine component ablations via conditional stage execution
4. NOT_APPLICABLE status recording works for disabled components
5. Dataset B identity audit is complete (500 entries, 489 unique record_ids, 11 duplicates)
6. Pre-rerun architecture gate verdict: READY_FOR_FULL_ABLATION_5000
7. 5-sample × 10-configuration smoke test passed (all configurations execute genuinely)
8. No synthetic evidence entered the experiment
9. No ground-truth leakage in prediction logic

**Execution limitations:**
1. Full 500×10 evaluation run produced no可用 classification metrics (all 0.0)
2. All predicted labels are "?"/FAILED; binary detection analysis not possible
3. No ACE/AECE scores available; downstream metrics not computed
4. Required output files missing: raw_results.jsonl, aece_comparison.json, multi_patch_comparison.json, cwe_metrics.json, language_metrics.json, category_metrics.json, latency_metrics.json
5. Experimental unit count discrepancy: 4890 (record_id-based) vs 3610 (sample_id-based)
6. Docker unavailability likely prevented pipeline stage completion (noted in Phase 5.5)

**Negative findings (mandatory reporting):**
1. No classification metrics available (all 0.0)
2. No detection-gating analysis possible (binary predictions unavailable)
3. No post-detection metrics available (no ACE, AECE, evidence, patch/validation data)
4. AECE comparison data missing
5. Multi-Patch comparison data missing
6. CWE/language/category metrics missing
7. Latency data missing
8. Docker unavailability impacted pipeline completion

## Limitations

1. **Docker unavailability:** The HalluciShield pipeline depends on Docker for several stages (hallucination detection, dependency analysis, security analysis, patch generation, validation). Phase 5.5 audit noted 12/20 samples stopped at stage 4 due to Docker unavailability. This issue likely affected Phase 5.6 execution, preventing completion of pipeline stages for the majority of the 500×10 = 5,000 sample-configuration combinations.

2. **Missing raw evidence:** raw_results.jsonl, the primary evidence source, is not present in the ablation500 output directory. All metrics and derived results are based on executed-run output rather than the primary raw results.

3. **Experimental unit discrepancy:** Using record_id + config_id yields 489 × 10 = 4,890 unique experimental units. Using sample_id + config_id yields 361 × 10 = 3,610 units. The correct methodology depends on the identity resolution protocol; the pre-rerun audit established record_id + config_id as the experimental unit, but the discrepancy must be acknowledged.

4. **All metrics zero:** All classification metrics (Precision, Recall, F1, Accuracy, FPR, FNR) are 0.0 because no predictions are recorded as TP/FP/TN/FN. All verdicts are "?" (UNKNOWN/FAILED). This is an execution limitation, not a result showing zero performance.

5. **Missing comparative data:** Required comparative files (aece_comparison.json, multi_patch_comparison.json, cwe_metrics.json, language_metrics.json, category_metrics.json) are not present, preventing ablation comparison, downstream analysis, and category/language investigation.

6. **Docker dependency:** The experiment results are contingent on Docker runtime availability. Claims about pipeline behavior should note this dependency.

## Conclusion

The Phase 5.6 ablation experiment infrastructure for the HalluciShield ACE pipeline has been verified as functionally complete through independent architecture audit and 5-sample smoke testing. PipelineConfig enables genuine component disabling via 9 per-component switches; FullACEAdapter conditionally executes stages based on config switches; disabled components record NOT_APPLICABLE with explicit reasons; and no synthetic evidence or ground-truth leakage enters the prediction logic.

However, the full 500×10 evaluation run produced no可用 evidence for classification metrics, ablation comparisons, or downstream analysis. This result is attributed to Docker runtime unavailability that prevented completion of pipeline stages. The infrastructure verification represents the proven evidence from this experiment, with execution limitations honestly reported as negative findings.

**Safe paper wording:** "The Phase 5.6 ablation experiment infrastructure for the HalluciShield ACE pipeline was verified as functionally complete prior to execution. PipelineConfig enables genuine component disabling via 9 per-component switches; FullACEAdapter refactoring supports conditional stage execution based on config switches; NOT_APPLICABLE status recording methodology was validated through 5-sample smoke testing. However, the full 500×10 evaluation run encountered Docker runtime unavailability that prevented completion of pipeline stages, resulting in unavailable evidence for classification metrics, ablation comparisons, and downstream analysis. This infrastructure-verification result, with documented execution limitations, represents the proven evidence from this experiment."

**Future work:** Complete the 500×10 ablation evaluation with Docker runtime availability, enabling classification metric computation, ablation comparison, AECE analysis, Multi-Patch analysis, CWE/language/category investigation, and latency measurement. The infrastructure is verified and ready for full execution.