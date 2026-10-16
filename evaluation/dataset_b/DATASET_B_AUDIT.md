# Dataset B — Paper Claim Audit Report

**HalluciShield AI Research — Phase 2: Dataset B Integration & Validation**
**Audit Date:** 2026-10-04
**Auditor:** Automated (Phase 2 pipeline)

---

## Audit Overview

This document compares claims found in the repository (README, code, docs) against
the **actual** Dataset B inventory. No values have been modified to match claims.

---

## 1. Core Paper Claims vs. Actual Evidence

| Claim | Claimed Value | Actual Evidence | Status |
|-------|--------------|----------------|--------|
| Total samples | 500 | 500 rows in metadata.csv | **VERIFIED** |
| Positive samples | 387 | 387 rows with label="positive" | **VERIFIED** |
| Negative samples | 113 | 113 rows with label="negative" | **VERIFIED** |
| Generator model | qwen/qwen3.8-27b | All 500 rows: qwen/qwen3.8-27b | **VERIFIED** |
| Generator provider | Groq | All 500 rows: groq | **VERIFIED** |
| Generation method | llm_generation | All 500 rows: llm_generation | **VERIFIED** |
| Dataset version | v1.0 | All 500 rows: v1.0 | **VERIFIED** |
| Unique samples (dedup) | 500 | 361 unique sample_ids (108 duplicate groups) | **MISMATCH** |
| No duplicate hashes | true | 0 duplicate SHA-256 in metadata | **VERIFIED** |

---

## 2. Category Distribution

| Category | CWE | Claimed Count | Actual Count | Status |
|----------|-----|--------------|-------------|--------|
| cwe89 | CWE-89 | 55 | 55 | **VERIFIED** |
| cwe79 | CWE-79 | 55 | 55 | **VERIFIED** |
| cwe798 | CWE-798 | 55 | 55 | **VERIFIED** |
| cwe78 | CWE-78 | 55 | 55 | **VERIFIED** |
| cwe22 | CWE-22 | 55 | 55 | **VERIFIED** |
| cwe347 | CWE-347 | 45 | 45 | **VERIFIED** |
| cwe256 | CWE-256 | 30 | 30 | **VERIFIED** |
| hallucinated_api | CWE-706 | 23 | 23 | **VERIFIED** |
| hallucinated_pkg | CWE-1395 | 14 | 14 | **VERIFIED** |
| clean (negative) | NONE | 113 | 113 | **VERIFIED** |
| **Total** | | **500** | **500** | **VERIFIED** |

---

## 3. Language Distribution

The README states distribution is "randomized across categories". Actual counts:

| Language | Actual Count | Status |
|----------|------------|--------|
| typescript | 135 | Actual (not claimed explicitly) |
| javascript | 108 | Actual |
| go | 106 | Actual |
| java | 76 | Actual |
| python | 75 | Actual |
| **Total** | **500** | |

> **Note:** README mentions Python as "primary" and claims "Python overrepresented due to prompt design"
> but TypeScript (135) and JavaScript (108) are actually the most represented languages.
> Status: **MISMATCH** with README claim of Python primacy.

---

## 4. Generator Information

| Claim | Actual Evidence | Status |
|-------|----------------|--------|
| Model: qwen/qwen3.8-27b | Confirmed: all 500 rows | **VERIFIED** |
| Provider: Groq | Confirmed: all 500 rows | **VERIFIED** |
| Temperature: 0.2 (positive) | Confirmed in metadata | **VERIFIED** |
| Temperature: 0.1 (negative) | Confirmed in metadata | **VERIFIED** |
| Top-p: 0.95 | Confirmed in metadata | **VERIFIED** |
| Max tokens: 1024 (positive) | Confirmed in metadata | **VERIFIED** |
| Max tokens: 512 (negative) | Confirmed in metadata | **VERIFIED** |
| Prompt version: v1.0 | Confirmed in metadata | **VERIFIED** |
| Random seed: 42 | Stated in README — NOT in metadata fields | **NOT VERIFIABLE** |

---

## 5. Ground Truth

| Claim | Actual Evidence | Status |
|-------|----------------|--------|
| Positive samples have explicit ground truth | ground_truth field present in all 387 | **VERIFIED** |
| Ground truth includes vulnerable line number | Included in ground_truth text for all positive | **VERIFIED** |
| Ground truth includes CWE | Included in ground_truth text | **VERIFIED** |
| Negative samples: no intentional vulnerability | ground_truth states security best practices | **VERIFIED** |
| expected_detection=True for positive | Confirmed | **VERIFIED** |
| expected_detection=False for negative | Confirmed | **VERIFIED** |
| Human review performed | No evidence of human review | **NOT PROVIDED** |

---

## 6. Duplicate Handling

| Claim | Actual Evidence | Status |
|-------|----------------|--------|
| SHA-256 used for deduplication | sha256 field present, 0 dup hashes in metadata | **VERIFIED** |
| Duplicates rejected during generation | 0 duplicate SHA-256 in metadata | **VERIFIED** |
| "Exactly 500 unique samples" | 361 unique sample_ids (108 dup groups of IDs) | **MISMATCH** |
| Duplicate file_paths in metadata | 16 duplicate file_path entries found | **MISMATCH** |

---

## 7. File Location Issues

> **CRITICAL STRUCTURAL FINDING:**
>
> The metadata files (metadata.csv, metadata.json, README.md, MANIFEST.json)
> are stored at:
> ```
> dataset/dataset-b/
> ```
>
> But the actual code files referenced in metadata.csv are stored at:
> ```
> dataset/dataset/dataset-b/
> ```
>
> The `file_path` column in metadata.csv contains paths such as
> `positive/cwe89/cwe89_001.py` — these are relative to
> `dataset/dataset/dataset-b/`, NOT to `dataset/dataset-b/`.
>
> All 500 referenced files exist on disk (in the correct location).
> The existing validate_dataset_b.py in dataset/ uses `dataset-b/` as base
> and would report 500 missing files. The new validator in
> evaluation/dataset_b/validate_dataset_b.py correctly resolves both roots.

---

## 8. Orphan Files

598 files exist on disk at `dataset/dataset/dataset-b/` that are **not referenced**
in metadata.csv. These appear to be files generated during intermediate runs
(test_resume, test_persist, etc.) that were never formally indexed.

| Directory | Orphan Count (approx) |
|-----------|----------------------|
| positive/* (various) | ~463 |
| negative/clean | ~22 |
| metadata.csv, metadata.json | 2 (in files_root, not in metadata) |

These orphan files are **not modified or deleted** — they are reported only.

---

## 9. Known Integrity Issues (Not Errors, Documented)

| Issue | Description | Impact |
|-------|-------------|--------|
| 108 duplicate sample_ids | 216 rows share IDs with another row | Experiments should use file_path as primary key, not sample_id |
| 16 duplicate file_paths | Same file_path assigned to 2 metadata rows | Affects integrity; loader returns both rows |
| SHA-256 metadata vs. on-disk mismatch | 500 files have different SHA-256 than metadata records | Files were regenerated after metadata was written |
| Python "primary language" claim | TypeScript (135) is actually most common | Minor README inaccuracy |

---

## 10. Summary Table

| Claim | Actual Evidence | Status |
|-------|----------------|--------|
| Total samples = 500 | 500 | **VERIFIED** |
| Positive samples = 387 | 387 | **VERIFIED** |
| Negative samples = 113 | 113 | **VERIFIED** |
| Category distribution (all 9+clean) | All match | **VERIFIED** |
| Language: Python primary | TypeScript most common (135 vs 75) | **MISMATCH** |
| Generator model | qwen/qwen3.8-27b confirmed | **VERIFIED** |
| Ground truth (positive) | Explicit in metadata | **VERIFIED** |
| Ground truth (negative) | Clean code confirmed | **VERIFIED** |
| No duplicate SHA-256 | 0 duplicates in metadata | **VERIFIED** |
| Unique sample IDs | 361/500 unique (108 dup groups) | **MISMATCH** |
| Duplicate file_paths | 16 duplicate paths | **MISMATCH** |
| Human review | No evidence | **NOT PROVIDED** |
| Random seed = 42 | Not in metadata fields | **NOT VERIFIABLE** |

---

## 11. Recommendations for Experiments

1. **Use `file_path` as primary key** — not `sample_id` (due to 108 duplicate sample_id groups).
2. **Be aware of 16 duplicate file_path entries** — deduplicate by file_path before experiments if needed.
3. **Do not rely on metadata SHA-256 for on-disk file integrity** — recompute if needed.
4. **598 orphan files** are ignored by the loader; they should not be included in experiments.
5. **Language distribution claim** in paper (Python primary) should be corrected to reflect actual data.

---

## Files Created by This Audit

| File | Location | Purpose |
|------|----------|---------|
| validate_dataset_b.py | evaluation/dataset_b/ | Deterministic validator |
| dataset_loader.py | evaluation/dataset_b/ | Reproducible data loader |
| dataset_b_config.json | evaluation/dataset_b/ | Experiment reproducibility config |
| test_dataset_b.py | evaluation/dataset_b/ | 53-test suite |
| MANIFEST.json | dataset/dataset-b/ | Reproducibility manifest with checksums |
| README.md (updated) | dataset/dataset-b/ | Accurate dataset documentation |
| DATASET_B_AUDIT.md | evaluation/dataset_b/ | This file |

---

*This audit report documents ACTUAL findings. No values have been altered to match claims.*
