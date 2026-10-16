# IEEE-Ready Tables: Phase 5.6 Ablation Experiment

**Note:** Tables reflect available evidence from experiment artifacts. Missing data is explicitly noted.

## Table 1: Dataset and Experimental-Unit Summary

| Metric | Value | Source | Notes |
|--------|-------|--------|-------|
| Total manifest entries | 500 | config.json | 500 samples × 10 configurations |
| Unique record_ids | 489 | Dataset identity audit | SHA-256 based identities |
| Duplicate record_id entries | 11 | Dataset identity audit | Across 10 groups, all exact duplicates |
| Unique sample_ids | 361 | trace_summary.json | 361 unique sample_ids out of 500 |
| Unique experimental_units (record_id-based) | 4,890 | config.json | 489 × 10 |
| Unique experimental_units (sample_id-based) | 3,610 | provenance_summary.json | 361 × 10 |
| Manifest executions | 5,000 | config.json | 500 × 10 |
| Duplicate experimental_units | 110 (record_id) / 590 (sample_id) | config.json / provenance_summary | Discrepancy in counting methodology |

## Table 2: A-J Ablation Classification Metrics

| Config | Ablation | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy | FPR | FNR |
|--------|----------|----|----|----|----|-----------|--------|----|----------|-----|-----|
| A | Full | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| B | Hallucination OFF | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| C | Dependency OFF | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| D | Security OFF | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| E | Risk OFF | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| F | Patch OFF | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| G | Validation OFF | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| H | Legacy ACE OFF | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| I | AECE OFF | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| J | Multi-Patch OFF | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

**Note:** All classification metrics are 0.0 because predictions are recorded as "?"/FAILED, not as TP/FP/TN classifications. Binary detection analysis not possible from current artifacts.

## Table 3: A-J Downstream Confidence/Evidence/Patch Metrics

| Config | Ablation | ACE Score | AECE Score | Evidence Completeness | Patch Candidates | Validation Status | Decision |
|--------|----------|-----------|------------|----------------------|------------------|-------------------|----------|
| A | Full | N/A | N/A | N/A | 0 | NOT_APPLICABLE | ? |
| B | Hallucination OFF | N/A | N/A | N/A | 0 | NOT_APPLICABLE | ? |
| C | Dependency OFF | N/A | N/A | N/A | 0 | NOT_APPLICABLE | ? |
| D | Security OFF | N/A | N/A | N/A | 0 | NOT_APPLICABLE | ? |
| E | Risk OFF | N/A | N/A | N/A | 0 | NOT_APPLICABLE | ? |
| F | Patch OFF | N/A | N/A | N/A | 0 | NOT_APPLICABLE | ? |
| G | Validation OFF | N/A | N/A | N/A | 0 | NOT_APPLICABLE | ? |
| H | Legacy ACE OFF | N/A | N/A | N/A | 0 | NOT_APPLICABLE | ? |
| I | AECE OFF | N/A | N/A | N/A | 0 | NOT_APPLICABLE | ? |
| J | Multi-Patch OFF | N/A | N/A | N/A | 0 | NOT_APPLICABLE | ? |

**Note:** All downstream metrics have N/A or 0 values because ACE/AECE scores were not computed (sample_count=0 in trace_summary). Validation decisions are all "?" (UNKNOWN).

## Table 4: AECE vs Legacy ACE

| Comparison | Legacy ACE Mean | AECE Mean | Difference | Sample Count | Status |
|------------|----------------|-----------|------------|--------------|--------|
| A vs I | N/A | N/A | N/A | 0 | File aece_comparison.json missing |

**Note:** AECE comparison data not available in current experiment artifacts.

## Table 5: Multi-Patch ON vs OFF

| Comparison | Candidate Count | Selected Patch | Selection Score | Validation Outcome | Status |
|------------|----------------|----------------|-----------------|--------------------|--------|
| J (Multi-Patch OFF) vs A (FULL) | N/A | N/A | N/A | N/A | File multi_patch_comparison.json missing |

**Note:** Multi-Patch comparison data not available in current experiment artifacts.

## Table 6: CWE-wise Results

| CWE | Sample Count | Precision | Recall | F1 | Status |
|-----|--------------|-----------|--------|----|--------|
| N/A | N/A | N/A | N/A | N/A | File cwe_metrics.json missing |

**Note:** CWE-wise results not available in current experiment artifacts.

## Table 7: Language-wise Results

| Language | Sample Count | Precision | Recall | F1 | Status |
|----------|--------------|-----------|--------|----|--------|
| N/A | N/A | N/A | N/A | N/A | File language_metrics.json missing |

**Note:** Language-wise results not available in current experiment artifacts.

## Table 8: Latency Comparison

| Config | Mean Latency (ms) | Median Latency (ms) | P95 Latency (ms) | P99 Latency (ms) | Status |
|--------|-------------------|---------------------|------------------|------------------|--------|
| A | N/A | N/A | N/A | N/A | Raw results missing |
| B | N/A | N/A | N/A | N/A | Raw results missing |
| C | N/A | N/A | N/A | N/A | Raw results missing |
| D | N/A | N/A | N/A | N/A | Raw results missing |
| E | N/A | N/A | N/A | N/A | Raw results missing |
| F | N/A | N/A | N/A | N/A | Raw results missing |
| G | N/A | N/A | N/A | N/A | Raw results missing |
| H | N/A | N/A | N/A | N/A | Raw results missing |
| I | N/A | N/A | N/A | N/A | Raw results missing |
| J | N/A | N/A | N/A | N/A | Raw results missing |

**Note:** Latency data not available because raw_results.jsonl is missing from ablation500 directory.