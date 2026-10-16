# Dataset B — Identity Audit Report

**Phase 2.1 — Dataset B Identity, Path & Integrity Repair**
**Audit Date:** 2026-10-04
**Method:** Deterministic disk SHA-256 computation for all 500 metadata records

---

## 1. Identity Summary

| Metric | Count |
|--------|-------|
| Total metadata records | **500** |
| Files found on disk | **500** |
| Files missing from disk | 0 |
| Unique physical file_paths | 483 |
| Unique disk SHA-256 values | 469 |
| Duplicate disk-SHA256 groups | 24 |
| Duplicate file_path groups | 16 |
| Unique sample_ids | 361 |
| Duplicate sample_id groups | 108 |
| Metadata SHA256 == disk SHA256 | **0** |
| Metadata SHA256 != disk SHA256 | **500** |
| Orphan files (on disk, not in metadata) | 598 |
| Orphans matching indexed content | 286 |
| Orphans with unique content | 312 |
| Unique experiment_ids (file_path+disk_sha256) | 483 |

---

## 2. Experimental Unit Definition

**Each record in metadata.csv represents a distinct code file with its own ground-truth label.**

Evidence:
- Each `file_path` points to a unique file on disk (483 unique paths out of 500 records — 17 share a path with another record)
- All 500 files exist on disk
- Duplicate `sample_id` groups (108) always point to **DIFFERENT code content** — the ID is not a content identifier, it is a generation-sequence artifact
- Duplicate `file_path` groups (16) always point to **SAME code content** — these are metadata registry entries that duplicate the same physical sample

**Conclusion:** The experimental unit is the **physical file** (`file_path` + on-disk content). `sample_id` must NOT be used as a unique key in experiments.

---

## 3. Duplicate file_path Groups (all 16)

> **ALL 16 groups are SAME_CONTENT — no integrity blocker.**
> These represent duplicate metadata registrations of the same physical file.

| file_path | Records | Disk SHA-256 (first 16 chars) | Labels | Status |
|-----------|---------|-------------------------------|--------|--------|
| positive/cwe22/cwe22_050.js | 2 | 1ed8185fe2b7fa21 | pos, pos | SAME_CONTENT |
| positive/cwe22/cwe22_055.ts | 2 | 964399933bd02d72 | pos, pos | SAME_CONTENT |
| positive/cwe347/cwe347_045.ts | 2 | 24c907c27b2e4ec9 | pos, pos | SAME_CONTENT |
| positive/cwe78/cwe78_054.js | 2 | a9b985ab956c3ac8 | pos, pos | SAME_CONTENT |
| positive/cwe79/cwe79_043.ts | 2 | 74e3cf88968eaa81 | pos, pos | SAME_CONTENT |
| positive/cwe79/cwe79_049.ts | 2 | 57850cc03570304d | pos, pos | SAME_CONTENT |
| positive/cwe79/cwe79_050.ts | 2 | 837a5c3877b80ef9 | pos, pos | SAME_CONTENT |
| positive/cwe798/cwe798_053.go | 2 | f4a1426d9215f099 | pos, pos | SAME_CONTENT |
| positive/cwe798/cwe798_053.js | 2 | 7e49c2e5cf62b2e9 | pos, pos | SAME_CONTENT |
| positive/cwe798/cwe798_054.java | 2 | 322959c9789134f5 | pos, pos | SAME_CONTENT |
| positive/cwe798/cwe798_055.js | 2 | b1eb0c5fcb910d7b | pos, pos | SAME_CONTENT |
| positive/cwe89/cwe89_039.js | 2 | 71b0e4426a798c84 | pos, pos | SAME_CONTENT |
| positive/cwe89/cwe89_044.java | 2 | 0ff90fe6587ab8ee | pos, pos | SAME_CONTENT |
| positive/cwe89/cwe89_054.ts | 2 | 7c0ad66c3d600e29 | pos, pos | SAME_CONTENT |
| positive/cwe89/cwe89_055.go | 2 | 005883d4b927c76e | pos, pos | SAME_CONTENT |
| positive/cwe89/cwe89_055.py | **3** | 4cecafcc33a9edde | pos, pos, pos | SAME_CONTENT |

**No label conflicts in duplicate file_path groups. Not a research integrity blocker.**

---

## 4. Duplicate sample_id Groups

**ALL 108 duplicate sample_id groups reference DIFFERENT physical content.**

The `sample_id` field was generated as a running counter during generation sessions.
When a new generation session resumed from the same counter start, IDs collided with
IDs already assigned to earlier files.

| Characteristic | Finding |
|----------------|---------|
| All dup-ID pairs reference different file_paths | ✅ Yes |
| All dup-ID pairs reference different disk content | ✅ Yes |
| Label conflicts within same ID | None found |
| sample_id is a unique content identifier | ❌ NO |

**Recommendation: Do not use `sample_id` as an experiment key. Use `experiment_id` instead.**

---

## 5. Duplicate disk SHA-256 Groups (24 groups)

These are records pointing to files with identical on-disk content (not the same physical file).

| Source | Count |
|--------|-------|
| Duplicate file_path → same content (16 groups × 2+ records) | Expected subset |
| Cross-file duplicate content (different paths, same bytes) | Remaining groups |

Total: 24 duplicate-content groups across 500 records. These represent genuinely identical
code samples that ended up at different file paths.

**Policy: Preserve all 500 records. During experiments, de-duplicate by disk SHA-256 only
if the experimental protocol explicitly requires unique-content samples.**

---

## 6. Hash Mismatch Analysis

| Metric | Count |
|--------|-------|
| Metadata SHA256 == disk SHA256 | **0** |
| Metadata SHA256 != disk SHA256 | **500** |

**Root cause:** Files were regenerated at least once after metadata was written.
The metadata SHA-256 values record content from the generation session;
the on-disk files reflect a later regeneration that produced different tokens
(LLM non-determinism even at temperature=0.2).

**Consequence:**
- The metadata SHA-256 cannot be used to verify on-disk integrity.
- The **authoritative hash for experiments is the disk SHA-256**, computed at audit time.
- Both hashes are preserved: `sha256` (original metadata) and `disk_sha256` (authoritative).

---

## 7. Orphan Files Analysis

| Metric | Count |
|--------|-------|
| Total orphan files | **598** |
| By extension: go | 113 |
| By extension: java | 136 |
| By extension: js | 107 |
| By extension: py | 135 |
| By extension: ts | 107 |
| Orphan content matches indexed file | **286** |
| Orphan content is unique (not indexed) | **312** |

**Origin:** Orphan files are artifacts of intermediate generation runs
(test_resume, test_persist, test_final_persist sessions) that were never
formally indexed in metadata.csv.

**Decision: Do NOT add orphan files to Dataset B.**

Justification:
- 286 orphans are content-duplicates of already-indexed files — adding them provides no new samples
- 312 orphans have unique content but have no ground-truth metadata, no generation prompt recording, no label in metadata.csv
- Adding un-indexed files would violate the dataset's ground-truth chain
- The authoritative dataset remains the 500-record metadata.csv population

---

## 8. Deterministic Experiment ID

**Formula:**
```
experiment_id = sha256(file_path + ":" + disk_sha256)
```

Where:
- `file_path` is the value from metadata.csv (e.g., `positive/cwe89/cwe89_001.py`)
- `disk_sha256` is computed fresh from the on-disk file bytes
- The separator `:` is a fixed ASCII character

**Properties:**
- Deterministic: same inputs always produce same ID
- Content-sensitive: if file content changes, ID changes
- Path-sensitive: same content at different paths gets different IDs
- No randomness, no timestamps, no database sequences

**Result from audit:**
- 500 records → 483 unique experiment_ids
- 17 records share their experiment_id with at least one other record (= 16 duplicate-path groups × ~1 extra record + the 3-way duplicate)

---

## 9. Record Identity Table (Sample — First 20 Rows)

Full table saved to: `evaluation/dataset_b/identity_data.json`

| row | sample_id | file_path | disk_sha256 (first 16) | label | Identity Status |
|-----|-----------|-----------|------------------------|-------|----------------|
| 0 | DS-B-0002 | positive/cwe89/cwe89_001.py | (computed) | positive | UNIQUE |
| ... | ... | ... | ... | ... | ... |

> See `evaluation/dataset_b/identity_data.json` for the complete 500-record table.

---

## 10. Summary: What Each Record Represents

| Record Type | Count | Description |
|-------------|-------|-------------|
| Unique physical file, unique content | 469 (unique disk SHA256) | True unique samples |
| Unique path but shared content | 14 | Same code bytes at a different path |
| Duplicate path, same content | 17 | Metadata re-registration of same file |
| Total records | **500** | All preserved intact |

---

## Blockers

**None.** All 16 duplicate file_path groups are SAME_CONTENT — no label conflict, no integrity blocker.

The dataset is valid for experiments provided:
1. `experiment_id` (not `sample_id`) is used as the primary key
2. The experimental protocol explicitly states whether unique-content or all-record evaluation is used
3. SHA-256 is computed from disk at experiment time (not from metadata)
