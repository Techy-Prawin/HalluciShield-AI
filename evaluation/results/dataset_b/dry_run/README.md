# Dataset B Full ACE Benchmark Results (Phase 3.4)

- **Experiment Name:** phase-3-dataset-b-ace-evaluation
- **Version:** v2.0
- **Timestamp:** 2026-10-05T07:25:54.286868+00:00
- **Total Records:** 2 (Positive: 1, Negative: 1)
- **Manifest Hash:** `e4489ccc0ca5b9c2`

## Executive Summary

| System | Precision | Recall | F1 | Accuracy | FPR | FNR | Coverage | TP | FP | TN | FN | Mean Latency (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **semgrep** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 1 | 0 | 1 | 0 | 0.0 |
| **llm_zero_shot** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 1 | 0 | 1 | 0 | 1082.5 |
| **sandbox** | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 0 | 0 | 0.0 |
| **full_ace** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 1 | 0 | 1 | 0 | 1183.5 |

## Reproduction Command

```bash
python evaluation/dataset_b/evaluator.py
```
