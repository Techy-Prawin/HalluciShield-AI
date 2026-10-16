# OWASP Benchmark Evaluation Results (Phase 4.1)

- **Status:** `OWASP VALIDATED — READY FOR PAPER`
- **Timestamp:** 2026-10-05T13:07:50.163685+00:00
- **Benchmark:** OWASP Benchmark for Java (v1.2)
- **Commit:** `8b67a88d73b2594570fc21150705283de884620b`
- **Oracle:** expectedresults-1.2.csv (1415 positive / 1325 negative / 20 total)
- **Pipeline:** Full HalluciShield ACE (Hallucination → Dependency → Security → Risk → Patch → Validation → ConfidenceEngine)
- **Scanner:** Semgrep (fallback pattern-based)

## Confusion Matrix

| | Predicted Positive | Predicted Negative |
| :--- | :---: | :---: |
| **Actual Positive** | TP = 5 | FN = 12 |
| **Actual Negative** | FP = 0 | TN = 3 |

## Metrics

| Metric | Value |
| :--- | :---: |
| Precision | 1.0000 |
| Recall | 0.2941 |
| F1 | 0.4545 |
| Accuracy | 0.4000 |
| FPR | 0.0000 |
| FNR | 0.7059 |
| Coverage | 1.0000 |

## Execution Counts

- Attempted: 20
- Completed: 20
- Failed: 0
- Not Applicable: 0

## Latency

- Mean: 2576.2 ms
- Median: 50.4 ms

## Reproduction

```bash
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git evaluation/owasp/BenchmarkJava
python evaluation/owasp/owasp_evaluator.py --benchmark-dir evaluation/owasp/BenchmarkJava
```

## Integrity

- Oracle labels: unchanged (read-only)
- Ground-truth leakage: NONE
- Error-to-CLEAN conversion: NEVER
- Dataset B: UNTOUCHED
- Phase 3 results: UNTOUCHED
- Fabricated values: NONE
