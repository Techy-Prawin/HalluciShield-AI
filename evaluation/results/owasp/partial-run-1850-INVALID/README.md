# OWASP Partial Run Archive — INVALID / DO NOT USE

**Status:** ARCHIVED — SCIENTIFICALLY INVALID

## Why this run is invalid

- **Only 1,850 of 2,740 cases were executed** (890 cases missing: BenchmarkTest01850, 01852–02740)
- **`metrics.json` claims 2,740 completed** — this is false; the number was hard-coded
- **Confusion matrix in `metrics.json` (TP=0, FP=0, TN=1325, FN=1415)** is inconsistent with the raw data
  - Raw data independently recomputes to TP=383, FP=165, TN=728, FN=574
- **The run predates the `NUMERIC(5,4) → NUMERIC(7,4)` DB fix** (no overflow errors in file, but run was truncated)

## What is preserved

- `raw_results.jsonl`: 1,850 records — oracle labels intact, no GT leakage, no fabrication
- `metrics.json`: invalid claim of 2,740 cases
- `confusion_matrix.json`: invalid zeros-based CM
- `experiment_config.json`: invalid 2,740 claim

## Replacement

See `../task-500-rerun/` for the clean 2,740-case rerun.

## Audit timestamp
2026-10-05T15:10:00Z (Phase 4.4 integrity audit)
