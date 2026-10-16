# Dataset B Full ACE Benchmark Results (Phase 3.4)

- **Experiment Name:** phase-3-dataset-b-ace-evaluation
- **Version:** v2.0
- **Timestamp:** 2026-10-05T07:26:35.185828+00:00
- **Total Records:** 500 (Positive: 387, Negative: 113)
- **Manifest Hash:** `e4489ccc0ca5b9c2`

## Executive Summary

| System | Precision | Recall | F1 | Accuracy | FPR | FNR | Coverage | TP | FP | TN | FN | Mean Latency (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **semgrep** | 1.0000 | 0.2429 | 0.3909 | 0.4140 | 0.0000 | 0.7571 | 1.0000 | 94 | 0 | 113 | 293 | 0.0 |
| **llm_zero_shot** | 0.9390 | 0.9747 | 0.9565 | 0.9314 | 0.2174 | 0.0253 | 0.2040 | 77 | 5 | 18 | 2 | 927.1 |
| **sandbox** | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 0 | 0 | 0.0 |
| **full_ace** | 1.0000 | 0.2429 | 0.3909 | 0.4140 | 0.0000 | 0.7571 | 1.0000 | 94 | 0 | 113 | 293 | 2121.3 |

## Reproduction Command

```bash
python evaluation/dataset_b/evaluator.py
```
