# Dataset B — HalluciShield AI-Generated Code Samples

**Version:** v1.0
**Audit Date:** 2026-10-04
**Status:** Validated

---

## 1. Dataset Purpose

Dataset B is a benchmark dataset of AI-generated code samples for evaluating
the HalluciShield AI security analysis pipeline.

It contains both vulnerable (positive) samples and clean (negative) samples,
generated using an LLM with deterministic prompts and recorded generation
parameters for full reproducibility.

---

## 2. Dataset Version

| Field | Value |
|-------|-------|
| Dataset version | v1.0 |
| metadata.csv SHA-256 | 263415aff6f7de922e84c373b488fe212f8d9d9fb7bd286e812ba165996dc344 |
| metadata.json SHA-256 | b2030c41729ceae344ed07e45ba03b3b7ba850543ee8f04f65c14a3ff031ea19 |
| Manifest | dataset/dataset-b/MANIFEST.json |

---

## 3. Actual Sample Counts (Validated)

| Metric | Count |
|--------|-------|
| Total rows in metadata.csv | 500 |
| Positive samples | 387 |
| Negative samples | 113 |
| Unique sample IDs | 361 |
| Duplicate sample_id groups | 108 |
| Duplicate file_path entries | 16 |
| Duplicate SHA-256 in metadata | 0 |
| Files found on disk | 500 |
| Orphan files on disk (not in metadata) | 598 |

---

## 4. Category / CWE Distribution (Actual)

| Category | CWE | Count | Vulnerability Type |
|----------|-----|-------|--------------------|
| cwe89 | CWE-89 | 55 | SQL Injection |
| cwe79 | CWE-79 | 55 | Cross-Site Scripting (XSS) |
| cwe798 | CWE-798 | 55 | Hardcoded Credentials |
| cwe78 | CWE-78 | 55 | OS Command Injection |
| cwe22 | CWE-22 | 55 | Path Traversal |
| cwe347 | CWE-347 | 45 | Improper JWT Verification |
| cwe256 | CWE-256 | 30 | Plaintext Storage of Passwords |
| hallucinated_api | CWE-706 | 23 | Hallucinated API Usage |
| hallucinated_pkg | CWE-1395 | 14 | Hallucinated Package Dependency |
| clean | NONE | 113 | Clean (no intentional vulnerability) |
| **Total** | | **500** | |

---

## 5. Languages (Actual)

| Language | Count |
|----------|-------|
| TypeScript | 135 |
| JavaScript | 108 |
| Go | 106 |
| Java | 76 |
| Python | 75 |

> **Note:** TypeScript is the most-represented language (135 samples), not Python.
> The README previously described Python as "primary" — this is inaccurate per actual data.

---

## 6. Generator Models

| Field | Value |
|-------|-------|
| Model | qwen/qwen3.8-27b |
| Provider | Groq |
| Method | llm_generation |
| Positive temperature | 0.2 |
| Negative temperature | 0.1 |
| Top-p | 0.95 |
| Positive max_tokens | 1024 |
| Negative max_tokens | 512 |
| Prompt version | v1.0 |

All 500 rows use the same model and provider.

---

## 7. Ground-Truth Methodology

### Positive Samples
Each positive sample has an explicit ground_truth field containing:
- Vulnerability type (e.g., SQL_INJECTION, CROSS_SITE_SCRIPTING)
- CWE number (e.g., CWE-89)
- Vulnerable line number
- Description of the vulnerability
- expected_detection: True

Ground truth was established at generation time by the LLM with explicit
prompting to introduce a specific, identified vulnerability.

**No independent human review was performed on positive sample labelling.**
Ground truth is LLM-asserted, not human-verified.

### Negative Samples
Each negative sample has:
- cwe: "NONE"
- category: "clean"
- label: "negative"
- expected_detection: False
- ground_truth: States no intentional vulnerability present

---

## 8. Clean Sample Methodology

Negative samples were generated with:
- Explicit prompt: "Generate clean secure code with no intentional vulnerabilities"
- Temperature: 0.1 (more deterministic than positive samples)
- max_tokens: 512

The LLM was instructed to follow security best practices. No independent
static analysis or manual audit was used to verify cleanliness.

---

## 9. Duplicate Handling

| Issue | Count | Status |
|-------|-------|--------|
| Duplicate SHA-256 in metadata | 0 | No content duplicates |
| Duplicate sample_id groups | 108 | Known issue — ID collision during generation |
| Duplicate file_path entries in metadata | 16 | Known issue — same path assigned twice |
| Orphan files (on disk, not in metadata) | 598 | Not indexed; excluded from experiments |

**Action for experiments:** Use `file_path` as the primary key, not `sample_id`.
The dataset loader in `evaluation/dataset_b/dataset_loader.py` handles this correctly.

---

## 10. Metadata Schema

| Field | Type | Description |
|-------|------|-------------|
| sample_id | string | Identifier (DS-B-XXXX) — NOT unique in current dataset |
| language | string | python, javascript, typescript, java, go |
| cwe | string | CWE-89, CWE-79, ... or NONE |
| category | string | cwe89, cwe79, ..., clean |
| label | string | positive or negative |
| generator_model | string | qwen/qwen3.8-27b |
| generation_prompt | string | Prompt used for generation |
| ground_truth | string | Ground truth description |
| file_path | string | Relative path from dataset/dataset/dataset-b/ |
| sha256 | string | SHA-256 at generation time (may differ from on-disk) |
| generator_provider | string | groq |
| temperature | float | LLM temperature |
| top_p | float | LLM top-p |
| max_tokens | int | Max tokens |
| prompt_version | string | v1.0 |
| timestamp | string | ISO 8601 UTC generation timestamp |
| generation_method | string | llm_generation |
| dataset_version | string | v1.0 |
| vulnerability_type | string | SQL_INJECTION, CROSS_SITE_SCRIPTING, etc. |
| severity | string | CRITICAL, HIGH, MEDIUM, NONE |
| description | string | Human description |
| expected_detection | boolean | true for positive, false for negative |
| expected_patch_types | array | JSON array (currently empty) |

---

## 11. File Location

> **IMPORTANT:** There are two dataset-b directories:
>
> - `dataset/dataset-b/` — contains metadata files ONLY (metadata.csv, metadata.json, README.md, MANIFEST.json)
> - `dataset/dataset/dataset-b/` — contains the actual code files
>
> The `file_path` column in metadata.csv is relative to `dataset/dataset/dataset-b/`.

---

## 12. Validation Procedure

```bash
# From repository root:
python evaluation/dataset_b/validate_dataset_b.py

# Skip SHA-256 hash check for speed:
python evaluation/dataset_b/validate_dataset_b.py --no-hash-check

# Strict mode (warnings become errors):
python evaluation/dataset_b/validate_dataset_b.py --strict

# Custom paths:
python evaluation/dataset_b/validate_dataset_b.py \
    --metadata-csv path/to/metadata.csv \
    --files-root path/to/code/files
```

Exit code 0 = PASS, 1 = FAIL (structural errors).

---

## 13. SHA-256 / Reproducibility Information

| File | SHA-256 |
|------|---------|
| metadata.csv | 263415aff6f7de922e84c373b488fe212f8d9d9fb7bd286e812ba165996dc344 |
| metadata.json | b2030c41729ceae344ed07e45ba03b3b7ba850543ee8f04f65c14a3ff031ea19 |

Full sample-level manifest: `dataset/dataset-b/MANIFEST.json`

---

## 14. Known Limitations

1. **108 duplicate sample_id groups** — The generation pipeline assigned the same
   sample_id to multiple distinct files. sample_id is NOT a unique identifier.
   Use `file_path` as primary key.

2. **16 duplicate file_path entries** — 16 file paths appear twice in metadata.csv
   with different metadata. This is a generation artifact.

3. **SHA-256 mismatch** — SHA-256 values recorded in metadata were computed at
   generation time. The on-disk files may have been regenerated, resulting in
   different hashes. The metadata SHA-256 should not be used for on-disk verification.

4. **598 orphan files** — Files on disk at `dataset/dataset/dataset-b/` that are not
   referenced in metadata.csv. These are generation artifacts and should be excluded
   from experiments.

5. **No human review** — All labelling is LLM-asserted, not human-verified.

6. **Language distribution** — TypeScript (135) is the most common language,
   not Python (75) as stated in earlier README versions.

7. **No train/test/validation splits** — The dataset has no predefined splits.
   If splits are needed for experiments, they must be created deterministically
   using a fixed seed.

---

## 15. How to Run Validation

```bash
# Full validation from repo root:
python evaluation/dataset_b/validate_dataset_b.py

# Run all Dataset B tests:
pytest evaluation/dataset_b/test_dataset_b.py -v
```

Both commands exit 0 on pass, non-zero on structural failure.

---

## Citation

```
HalluciShield Dataset B v1.0
500 AI-generated code samples for security analysis evaluation
Generated with Groq qwen/qwen3.8-27b
metadata.csv SHA-256: 263415aff6f7de922e84c373b488fe212f8d9d9fb7bd286e812ba165996dc344
```

---

## License

Dataset B is part of the HalluciShield research project. For academic/research use only.
