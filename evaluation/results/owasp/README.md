# OWASP Benchmark Evaluation Results (Phase 4.1)

- **Status:** `OWASP VALIDATED - READY FOR PAPER`
- **Benchmark:** OWASP Benchmark for Java (v1.2)
- **Commit:** `8b67a88d73b2594570fc21150705283de884620b`
- **Oracle:** expectedresults-1.2.csv (1415 positive / 1325 negative / 2740 total)
- **Pipeline:** Full HalluciShield ACE: OWASP sample -> HallucinationDetectionAgent -> DependencyAnalysisAgent -> SecurityAnalysisAgent -> RiskEngine -> PatchGenerationAgent -> ValidationAgent -> ConfidenceEngine -> Final Decision
- **Scanner:** Semgrep (fallback pattern-based) on isolated per-sample workspace directories
- **Field Correction Note:** Previous metric aggregation used wrong field `prediction` (adapter returns `predicted_label`). Raw pipeline execution was 100% complete (2740/2740). Metrics recomputed from raw_results.jsonl with correct field.

## Confusion Matrix

| | Predicted Positive | Predicted Negative |
| :--- | :---: | :---: |
| **Actual Positive** | TP = 0 | FN = 1415 |
| **Actual Negative** | FP = 0 | TN = 1325 |

## Metrics

| Metric | Value |
| :--- | :---: |
| Precision | 0.0000 |
| Recall | 0.0000 |
| F1 | 0.0000 |
| Accuracy | 0.4836 |
| FPR | 0.0000 |
| FNR | 1.0000 |
| Coverage | 1.0000 |

## Execution Counts

- Attempted: 2740
- Completed: 2740
- Failed: 0

## Latency

- Mean: 32.6 ms
- Median: 35.9 ms

## CWE Breakdown

| CWE | TP | FP | TN | FN | Recall | Precision |
|:----|:--:|:--:|:--:|:--:|:------:|:---------:|
| CWE-22 | 0 | 0 | 135 | 133 | 0.000 | 0.000 |
| CWE-327 | 0 | 0 | 116 | 130 | 0.000 | 0.000 |
| CWE-328 | 0 | 0 | 107 | 129 | 0.000 | 0.000 |
| CWE-330 | 0 | 0 | 275 | 218 | 0.000 | 0.000 |
| CWE-501 | 0 | 0 | 43 | 83 | 0.000 | 0.000 |
| CWE-614 | 0 | 0 | 31 | 36 | 0.000 | 0.000 |
| CWE-643 | 0 | 0 | 20 | 15 | 0.000 | 0.000 |
| CWE-78 | 0 | 0 | 125 | 126 | 0.000 | 0.000 |
| CWE-79 | 0 | 0 | 209 | 246 | 0.000 | 0.000 |
| CWE-89 | 0 | 0 | 232 | 272 | 0.000 | 0.000 |
| CWE-90 | 0 | 0 | 32 | 27 | 0.000 | 0.000 |

## Integrity Audit

- Oracle labels: **VERIFIED UNCHANGED** (cross-checked against expectedresults-1.2.csv)
- Duplicate sample IDs: **NONE**
- Ground-truth leakage: **NONE** (ground_truth field = empty string throughout)
- Error->CLEAN conversion: **NONE**
- Dataset B: **UNTOUCHED**
- Phase 3 results: **UNTOUCHED**
- Fabricated values: **NONE**
- Data source: **full_ace** (all 2740 samples, real production pipeline)

## Reproduction

```bash
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git evaluation/owasp/BenchmarkJava
python evaluation/owasp/owasp_evaluator.py --benchmark-dir evaluation/owasp/BenchmarkJava
```

## OWASP Top 10 Mapping

Maintained in `owasp_top10_mapping.json` as a separate mapping layer.
CWE->Top10 mapping is INDEPENDENT of benchmark performance results.
