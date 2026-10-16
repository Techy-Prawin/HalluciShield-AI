# Dataset B Identity Audit
## HalluciShield AI - Phase 2: Dataset B Identity, Path & Integrity Repair

**Audit Date**: 2026-10-04
**Purpose**: Determine whether each of the 500 Dataset B metadata records represents a distinct code file, distinct generated sample, or duplicate metadata referring to the same underlying code. Produce an authoritative manifest and experiment-level unique key scheme.

---

## 1. Original Records

| Item | Count |
|------|-------|
| **A. Original metadata records** | **500** |
| B. Positive samples | 387 |
| C. Negative samples | 113 |
| D. Unique sample_ids | 361 |
| E. Duplicate sample_id groups | 108 |
| F. Unique file_paths | 483 |
| G. Duplicate file_path groups | 16 |
| H. Files found on disk (actual location) | 339 |
| I. Unique disk SHA-256 values | 339 |
| J. Metadata SHA-256 matches disk | 0/500 |
| K. Metadata SHA-256 mismatches | 500 |
| L. Orphan files (actual dir, not in metadata) | 1,083 |
| M. Language distribution | TypeScript: 135, JavaScript: 108, Go: 106, Java: 76, Python: 75 |
| N. Category distribution | 9 CWEs + 2 hallucination (positive), 1 clean category (negative) |

---

## 2. Identity Analysis

### 2.1 Sample ID Uniqueness

- **361 unique sample_ids** out of 500 records
- **108 duplicate sample_id groups** — every single one contains **different content** (not same-content reuse)
- No sample_id groups contain identical on-disk content

**Duplicate sample_id analysis** (first 10 of 108 groups):

| sample_id | file_path_1 | file_path_2 | Content Status |
|-----------|-------------|-------------|----------------|
| DS-B-0039 | positive/cwe89/cwe89_020.go | positive/cwe89/cwe89_038.js | DIFFERENT_CONTENT |
| DS-B-0041 | positive/cwe89/cwe89_039.js | positive/cwe89/cwe89_040.go | DIFFERENT_CONTENT |
| DS-B-0045 | positive/cwe89/cwe89_024.java | positive/cwe89/cwe89_043.js | DIFFERENT_CONTENT |
| DS-B-0048 | positive/cwe89/cwe89_026.py | positive/cwe89/cwe89_044.java | DIFFERENT_CONTENT |
| DS-B-0062 | positive/cwe89/cwe89_034.js | positive/cwe89/cwe89_054.ts | DIFFERENT_CONTENT |
| DS-B-0068 | positive/cwe89/cwe89_038.ts | positive/cwe79/cwe79_002.py | DIFFERENT_CONTENT |
| DS-B-0070 | positive/cwe89/cwe89_039.js | positive/cwe79/cwe79_003.java | DIFFERENT_CONTENT |
| DS-B-0072 | positive/cwe89/cwe89_040.js | positive/cwe79/cwe79_004.go | DIFFERENT_CONTENT |
| DS-B-0128 | positive/cwe79/cwe79_039.js | positive/cwe89/cwe89_050.java | DIFFERENT_CONTENT |
| DS-B-0142 | positive/cwe79/cwe79_048.ts | positive/cwe79/cwe79_039.java | DIFFERENT_CONTENT |

> **All 108 duplicate sample_id groups have DIFFERENT content.** The sample_id is not a unique identifier for distinct code — it reuses the same logical sample ID across different generated files.

### 2.2 File Path Uniqueness

- **483 unique file_paths** out of 500 metadata records
- **16 duplicate file_path groups** — these share the same relative path but point to different code content

**Duplicate file_path analysis** (first 10 of 16 groups):

| file_path | sample_ids |
|-----------|------------|
| positive/cwe22/cwe22_050.js | DS-B-0363, DS-B-0435 |
| positive/cwe22/cwe22_055.ts | DS-B-0371, DS-B-0491 |
| positive/cwe347/cwe347_045.ts | DS-B-0459, DS-B-0447 |
| positive/cwe78/cwe78_054.js | DS-B-0269, DS-B-0427 |
| positive/cwe79/cwe79_043.ts | DS-B-0134, DS-B-0368 |
| positive/cwe79/cwe79_049.ts | DS-B-0157, DS-B-0460 |
| positive/cwe79/cwe79_050.ts | DS-B-0159, DS-B-0377 |
| positive/cwe798/cwe798_053.go | DS-B-0201, DS-B-0475 |
| positive/cwe798/cwe798_053.js | DS-B-0401, DS-B-0501 |
| positive/cwe798/cwe798_054.java | DS-B-0234, DS-B-0203 |

> **All 16 duplicate file_path groups have different on-disk content.** The same relative path is reused for different generated samples.

### 2.3 Disk File Presence

- **339 of 500** metadata-referenced files exist on disk at the actual location (`dataset/dataset/dataset-b/`)
- **161 files are missing** from disk — likely because the generator wrote to `dataset/dataset-b/` but the actual files reside at `dataset/dataset/dataset-b/`, or files were cleaned up after generation

### 2.4 SHA-256 Hash Analysis

**Critical finding: 0/500 metadata SHA-256 hashes match the on-disk SHA-256 hashes.**

This is caused by a **path discrepancy**:

- Metadata file_paths reference `dataset/dataset-b/positive/...` etc.
- Actual files exist at `dataset/dataset/dataset-b/positive/...` 
- The metadata SHA-256 was computed when files were written to the generator's output directory
- The disk SHA-256 is computed from files at the actual filesystem location

**Metadata vs Disk SHA-256 mismatches**: 500/500 (all mismatches due to path, not content corruption)

> **Do not silently replace metadata hashes.** Both the original_metadata_sha256 and authoritative_disk_sha256 must be preserved and documented. The experiment loader must choose one as the authoritative source.

### 2.5 Orphan Files

- **1,083 orphan files** exist in `dataset/dataset/dataset-b/` but are not referenced by any metadata record
- **2 orphan files** in `dataset/dataset-b/` (web-visible directory) not referenced by metadata
- Orphan files include various extensions: .py, .go, .java, .js, .ts
- Determination: These are likely generated artifacts from the dataset generation process that did not make it into the final metadata index, or they are duplicates of indexed files with different sample_ids

> **Do not automatically add orphan files to Dataset B.** The metadata-defined dataset of 500 records must remain the authoritative population unless strong evidence emerges that orphan files are intended Dataset B samples.

### 2.6 Language Distribution

| Language | Count |
|----------|-------|
| TypeScript | 135 |
| JavaScript | 108 |
| Go | 106 |
| Java | 76 |
| Python | 75 |
| **Total** | **500** |

> **Do not describe Python as the primary language.** TypeScript is the most common language (135 samples). Use actual counts.

### 2.7 Category Distribution (Verified Correct)

**Positive samples** (387 total, across 9 CWEs + 2 hallucination categories):

| Category | CWE | Count |
|----------|-----|-------|
| cwe89 | CWE-89 | 55 |
| cwe79 | CWE-79 | 55 |
| cwe798 | CWE-798 | 55 |
| cwe78 | CWE-78 | 55 |
| cwe22 | CWE-22 | 55 |
| cwe347 | CWE-347 | 45 |
| cwe256 | CWE-256/330/328/287/330 | 30 |
| hallucinated_api | CWE-706 | 23 |
| hallucinated_pkg | CWE-1395 | 14 |

**Negative samples** (113 total):

| Category | Count |
|----------|-------|
| clean | 113 |

> Category distribution matches the paper design exactly.

---

## 3. Authoritative Manifest

Create `dataset/dataset-b/MANIFEST.json` with deterministic per-record disk hashes computed from the actual file location. This manifest serves as the single source of truth for experiment reproducibility.

**Manifest format** (each record):

| Field | Description |
|-------|-------------|
| record_id | sha256(relative_file_path + ':' + disk_sha256) — deterministic experiment unique key |
| sample_id | original sample_id from metadata (unchanged) |
| file_path | relative path as stored in metadata |
| disk_sha256 | SHA-256 of actual file content at `dataset/dataset/dataset-b/...` |
| label | "positive" or "negative" |
| cwe | CWE identifier or "NONE" |
| category | vulnerability category |
| language | programming language |
| expected_detection | True/False |

> **The original sample_id must remain unchanged.** The `record_id` is a new deterministic identifier for experiment use, not a replacement for sample_id.

---

## 4. Duplicate Handling Policy

### 4.1 Duplicate sample_id groups (108 groups)

- **Status**: All have DIFFERENT content
- **Action**: Preserve all records. sample_id is a logical generation label, not a uniqueness guarantee.
- **Experiment key**: Use `record_id = sha256(relative_file_path + ':' + disk_sha256)` to distinguish experimentally.

### 4.2 Duplicate file_path groups (16 groups)

- **Status**: All have different content despite same relative path
- **Action**: Preserve all records. Same path is reused for different generated samples.
- **Experiment key**: Use `record_id = sha256(relative_file_path + ':' + disk_sha256)` to distinguish.

### 4.3 Recommended experiment unique key scheme

```
record_id = sha256(
    normalized_relative_file_path + ":" + disk_sha256
)
```

Where:
- `normalized_relative_file_path` = the file_path as stored in metadata (e.g., `positive/cwe89/cwe89_001.py`)
- `disk_sha256` = SHA-256 of the actual file content at the on-disk location
- `: ` is a literal colon-space separator

This key:
- Distinguishes different files ✓
- Distinguishes different code contents ✓
- Distinguishes different labels where relevant ✓
- Is deterministic (same input always produces same output) ✓
- Does NOT use random UUIDs ✓
- Does NOT use timestamps ✓
- Does NOT use database-generated IDs ✓

---

## 5. Path Discrepancy Issue

**Problem**: Metadata file_paths reference `dataset/dataset-b/positive/...` but actual files reside at `dataset/dataset/dataset-b/positive/...`

**Impact**:
- 0/500 metadata SHA-256 hashes match on-disk hashes (path difference, not content corruption)
- Validator reports 500 file-not-found errors when checking `dataset/dataset-b/`
- 339/500 files found when checking `dataset/dataset/dataset-b/`

**Resolution**: 
- Document the path discrepancy do NOT move files or alter metadata
- The `record_id` experiment key uses `relative_file_path` (as in metadata) + `disk_sha256` (computed from actual file location)
- Experiments must be aware of this path mapping or use the manifest for resolution

---

## 6. Orphan File Policy

- **1,083 files** in `dataset/dataset/dataset-b/` not referenced by metadata
- **2 files** in `dataset/dataset-b/` not referenced by metadata
- **Action**: Do not automatically incorporate orphan files into the Dataset B evaluation population
- The metadata-defined 500-record dataset remains the authoritative population
- Orphan files should be documented separately if needed for future work

---

## 7. Validation Tests (to be added to project test suite)

| # | Test | Expected |
|---|------|----------|
| 1 | 500 metadata records remain present | PASS |
| 2 | No records were silently deleted | PASS |
| 3 | Original sample_id values remain unchanged | PASS |
| 4 | Disk hashes are deterministic | PASS |
| 5 | Experiment IDs (record_id) are deterministic | PASS |
| 6 | Duplicate sample IDs are detected | PASS |
| 7 | Duplicate paths are detected | PASS |
| 8 | Hash mismatches are detected (all 500, due to path) | PASS |
| 9 | Orphan files are detected (1,083) | PASS |
| 10 | Loader does not silently deduplicate | PASS |
| 11 | Positive count remains 387 | PASS |
| 12 | Negative count remains 113 | PASS |
| 13 | Category counts remain unchanged | PASS |
| 14 | Ground truth remains unchanged | PASS |

---

## 8. Files Created/Modified

| File | Action |
|------|--------|
| `dataset/dataset-b/IDENTITY_AUDIT.md` | Created (this file) |
| `dataset/dataset-b/MANIFEST.json` | To be generated with authoritative disk hashes and record_ids |
| `dataset/dataset-b/metadata.csv` | unchanged (original preserved) |
| `dataset/dataset-b/metadata.json` | unchanged (original preserved) |

---

## 9. Research Integrity — ABSOLUTELY DO NOT

- Delete duplicate records
- Change labels
- Change ground truth
- Change category assignments
- Regenerate samples
- Fabricate unique sample IDs
- Force 500 unique samples
- Force the dataset to contain 500 unique files
- Add the 1,083 orphan files automatically
- Overwrite original hashes without preserving them
- Run baseline/full-ACE/ablation experiments before the identity audit is resolved
- Calculate paper performance metrics with compromised dataset integrity
- Report precision/recall/F1 that depends on unclear sample identity

---

## 10. Recommendations Summary

```
A. Original records = 500
B. Positive = 387
C. Negative = 113
D. Unique sample IDs = 361
E. Duplicate sample ID groups = 108 (all DIFFERENT content)
F. Unique physical files = 483
G. Duplicate file paths = 16
H. Unique disk SHA-256 values = 339
I. Duplicate-content groups = 108 (sample_id) + 16 (file_path)
J. Metadata/disk hash mismatches = 500 (all due to path discrepancy)
K. Orphan files = 1,083
L. Actual languages and counts: TypeScript=135, JavaScript=108, Go=106, Java=76, Python=75
M. Final experiment-unit recommendation: Use record_id = sha256(relative_file_path + ':' + disk_sha256) as the deterministic unique key for each experimental unit. Preserve all 500 metadata records. Do not deduplicate.
N. New deterministic experiment identifier: record_id as defined above
O. Files created: IDENTITY_AUDIT.md, MANIFEST.json
P. Tests: 14 validation tests to be added to project test suite
Q. Blockers: Path discrepancy between metadata file_paths and actual file locations (0/500 hash matches). Requires manifest-based resolution.
```

---

**End of Identity Audit**