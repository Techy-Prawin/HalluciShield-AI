# OWASP Benchmark Evaluation Results

- **Verdict:** `OWASP VALIDATED — READY FOR PAPER`
- **Benchmark:** OWASP Benchmark for Java (v1.2)
- **Commit:** `8b67a88d73b2594570fc21150705283de884620b`
- **Oracle:** expectedresults-1.2.csv (1415 positive / 1325 negative)
- **Expected cases:** 2740
- **Actual records in file:** 2740
- **Coverage complete:** True
- **Audit timestamp:** 2026-10-06T00:08:06.968731Z

## Confusion Matrix

|                 | Predicted Positive | Predicted Negative |
| :---            | :---:              | :---:              |
| **Actual Positive** | TP = 582      | FN = 833          |
| **Actual Negative** | FP = 256      | TN = 1069          |

## Metrics

| Metric    | Value        |
| :---      | :---:        |
| Precision | 0.6945 |
| Recall    | 0.4113    |
| F1        | 0.5166        |
| Accuracy  | 0.6026  |
| FPR       | 0.1932       |
| FNR       | 0.5887       |
| Coverage  | 1.0000  |

## Execution Counts

- Total records in file: 2740
- Scored (in CM): 2740
- Completed: 2740
- Failed: 0
- Timeout: 0
- Missing IDs: 0
- Duplicate IDs: 0

## Latency

- Mean: 345.6 ms
- Median: 38.0 ms
- P95: 1163.8 ms

## CWE Breakdown

| CWE | TP | FP | TN | FN | Recall | Precision |
|:----|:--:|:--:|:--:|:--:|:------:|:---------:|
| CWE-22 | 0 | 0 | 135 | 133 | 0.000 | 0.000 |
| CWE-327 | 72 | 0 | 116 | 58 | 0.554 | 1.000 |
| CWE-328 | 28 | 0 | 107 | 101 | 0.217 | 1.000 |
| CWE-330 | 193 | 0 | 275 | 25 | 0.885 | 1.000 |
| CWE-501 | 0 | 0 | 43 | 83 | 0.000 | 0.000 |
| CWE-614 | 0 | 0 | 31 | 36 | 0.000 | 0.000 |
| CWE-643 | 15 | 20 | 0 | 0 | 1.000 | 0.429 |
| CWE-78 | 33 | 30 | 95 | 93 | 0.262 | 0.524 |
| CWE-79 | 0 | 0 | 209 | 246 | 0.000 | 0.000 |
| CWE-89 | 241 | 206 | 26 | 31 | 0.886 | 0.539 |
| CWE-90 | 0 | 0 | 32 | 27 | 0.000 | 0.000 |

## Integrity Audit

- Oracle labels: **VERIFIED UNCHANGED**
- Duplicate sample IDs: **NONE**
- Ground-truth leakage: **NONE**
- Error→CLEAN conversion: **NONE**
- ACE overflow (>9.9999): **NONE**
- Dataset B: **UNTOUCHED**
- Fabricated values: **NONE**
- Prediction field: **predicted_label** (directly from FullACEAdapter)

## Reproduction

```bash
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git evaluation/owasp/BenchmarkJava
python evaluation/owasp/owasp_evaluator.py --benchmark-dir evaluation/owasp/BenchmarkJava --output-dir evaluation/results/owasp/task-500-rerun
python evaluation/owasp/audit_and_recompute.py --results-dir evaluation/results/owasp/task-500-rerun
```
