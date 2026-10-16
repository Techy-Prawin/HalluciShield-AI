#!/usr/bin/env python3
"""
Dataset B Test Suite - HalluciShield AI Research
==================================================
Tests for Dataset B loader, integrity, and reproducibility.

Run with:
    pytest evaluation/dataset_b/test_dataset_b.py -v

All tests are deterministic and do NOT modify source files.
"""

import csv
import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
METADATA_CSV = _REPO_ROOT / "dataset" / "dataset-b" / "metadata.csv"
FILES_ROOT = _REPO_ROOT / "dataset" / "dataset" / "dataset-b"

sys.path.insert(0, str(_REPO_ROOT))

VALID_LABELS = {"positive", "negative"}
VALID_CWES_POSITIVE = {
    "CWE-89", "CWE-79", "CWE-798", "CWE-78", "CWE-22",
    "CWE-347", "CWE-256", "CWE-706", "CWE-1395"
}
VALID_LANGUAGES = {"python", "javascript", "typescript", "java", "go"}


@pytest.fixture(scope="session")
def all_rows():
    """Load all rows from metadata.csv once per session."""
    assert METADATA_CSV.exists(), f"metadata.csv not found: {METADATA_CSV}"
    with open(METADATA_CSV, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    # Stable sort for determinism
    rows.sort(key=lambda r: (r.get("sample_id", ""), r.get("file_path", "")))
    return rows


@pytest.fixture(scope="session")
def loader():
    """Create a DatasetBLoader instance."""
    from evaluation.dataset_b.dataset_loader import DatasetBLoader
    return DatasetBLoader()


# ---------------------------------------------------------------------------
# 1. Dataset loads successfully
# ---------------------------------------------------------------------------

class TestDatasetLoads:
    def test_metadata_csv_exists(self):
        """metadata.csv must exist at the expected location."""
        assert METADATA_CSV.exists(), f"metadata.csv not found: {METADATA_CSV}"

    def test_files_root_exists(self):
        """Code files root directory must exist."""
        assert FILES_ROOT.exists(), f"files_root not found: {FILES_ROOT}"

    def test_csv_has_rows(self, all_rows):
        """metadata.csv must have at least one data row."""
        assert len(all_rows) > 0

    def test_csv_has_required_columns(self, all_rows):
        """metadata.csv must contain all required column names."""
        required = {
            "sample_id", "language", "cwe", "category", "label",
            "generator_model", "generation_prompt", "ground_truth",
            "file_path", "sha256",
        }
        actual_cols = set(all_rows[0].keys())
        missing = required - actual_cols
        assert not missing, f"Missing required columns: {missing}"

    def test_loader_initialises(self, loader):
        """DatasetBLoader must initialise without error."""
        assert loader is not None

    def test_loader_returns_samples(self, loader):
        """get_samples() must return a non-empty list."""
        samples = loader.get_samples()
        assert len(samples) > 0


# ---------------------------------------------------------------------------
# 2. Every indexed file exists
# ---------------------------------------------------------------------------

class TestFileExistence:
    def test_all_referenced_files_exist(self, all_rows):
        """Every file_path in metadata must exist under files_root."""
        missing = []
        for r in all_rows:
            fp = FILES_ROOT / r["file_path"].replace("/", os.sep)
            if not fp.exists():
                missing.append(r["file_path"])
        assert not missing, (
            f"{len(missing)} referenced file(s) missing on disk.\n"
            f"First 5: {missing[:5]}"
        )

    def test_positive_dir_exists(self):
        assert (FILES_ROOT / "positive").is_dir()

    def test_negative_dir_exists(self):
        assert (FILES_ROOT / "negative").is_dir()

    def test_clean_dir_exists(self):
        assert (FILES_ROOT / "negative" / "clean").is_dir()


# ---------------------------------------------------------------------------
# 3. Every sample has a unique sample_id (actual state: IDs are NOT unique)
# ---------------------------------------------------------------------------

class TestSampleIds:
    def test_total_sample_count(self, all_rows):
        """metadata.csv must have exactly 500 rows."""
        assert len(all_rows) == 500, f"Expected 500 rows, got {len(all_rows)}"

    def test_unique_ids_count(self, all_rows):
        """
        Dataset has 108 duplicate sample_id groups (known issue).
        Unique IDs should be 361 of 500.
        This test documents the ACTUAL state, not an expectation of uniqueness.
        """
        unique_ids = set(r["sample_id"] for r in all_rows)
        # Document actual state — 361 unique IDs out of 500 rows
        assert len(unique_ids) == 361, (
            f"Expected 361 unique IDs (known state), got {len(unique_ids)}"
        )

    def test_file_paths_are_mostly_unique(self, all_rows):
        """
        File paths in metadata are mostly unique.
        Known: 16 duplicate file_path entries. Assert < 5% duplicate file paths.
        """
        fp_counter = Counter(r["file_path"] for r in all_rows)
        dup_fps = {k: v for k, v in fp_counter.items() if v > 1}
        dup_ratio = len(dup_fps) / len(all_rows)
        assert dup_ratio < 0.05, (
            f"Too many duplicate file paths: {len(dup_fps)} ({dup_ratio:.1%})"
        )

    def test_no_empty_sample_ids(self, all_rows):
        """No sample_id field may be empty."""
        empty = [r["file_path"] for r in all_rows if not r.get("sample_id", "").strip()]
        assert not empty, f"Empty sample_ids: {empty[:5]}"


# ---------------------------------------------------------------------------
# 4. SHA-256 hashes are deterministic
# ---------------------------------------------------------------------------

class TestHashes:
    def test_sha256_field_not_empty(self, all_rows):
        """Every row must have a non-empty sha256 field."""
        empty = [r["sample_id"] for r in all_rows if not r.get("sha256", "").strip()]
        assert not empty, f"Empty sha256 fields: {empty[:5]}"

    def test_sha256_length(self, all_rows):
        """Every sha256 must be a 64-character hex string."""
        bad = [r["sample_id"] for r in all_rows if len(r.get("sha256", "")) != 64]
        assert not bad, f"Bad sha256 length: {bad[:5]}"

    def test_no_duplicate_sha256_in_metadata(self, all_rows):
        """No two metadata rows should have the same SHA-256 hash."""
        sha_counter = Counter(r["sha256"] for r in all_rows)
        dups = {k: v for k, v in sha_counter.items() if v > 1}
        assert not dups, f"Duplicate SHA-256 hashes in metadata: {len(dups)}"

    def test_sha256_is_deterministic(self, all_rows):
        """Computing SHA-256 twice on the same row must yield the same result."""
        # Pick first 3 rows that exist on disk
        checked = 0
        for r in all_rows:
            fp = FILES_ROOT / r["file_path"].replace("/", os.sep)
            if fp.exists():
                h1 = hashlib.sha256(fp.read_bytes()).hexdigest()
                h2 = hashlib.sha256(fp.read_bytes()).hexdigest()
                assert h1 == h2, f"Non-deterministic hash for {fp}"
                checked += 1
                if checked >= 3:
                    break
        assert checked > 0, "No files found on disk to test hash determinism"


# ---------------------------------------------------------------------------
# 5. Metadata schema is valid
# ---------------------------------------------------------------------------

class TestMetadataSchema:
    REQUIRED_FIELDS = [
        "sample_id", "language", "cwe", "category", "label",
        "generator_model", "generation_prompt", "ground_truth",
        "file_path", "sha256", "generator_provider",
    ]

    def test_all_required_fields_present(self, all_rows):
        """Every row must have all required fields with non-empty values."""
        errors = []
        for r in all_rows:
            for f in self.REQUIRED_FIELDS:
                if not str(r.get(f, "")).strip():
                    errors.append(f"[{r.get('sample_id')}] missing: {f!r}")
        assert not errors, f"{len(errors)} field error(s).\nFirst: {errors[:3]}"


# ---------------------------------------------------------------------------
# 6. Labels are valid
# ---------------------------------------------------------------------------

class TestLabels:
    def test_all_labels_valid(self, all_rows):
        """Every label must be 'positive' or 'negative'."""
        invalid = [r for r in all_rows if r.get("label") not in VALID_LABELS]
        assert not invalid, f"Invalid labels: {[(r['sample_id'], r['label']) for r in invalid[:5]]}"

    def test_positive_count(self, all_rows):
        pos = sum(1 for r in all_rows if r["label"] == "positive")
        assert pos == 387, f"Expected 387 positive, got {pos}"

    def test_negative_count(self, all_rows):
        neg = sum(1 for r in all_rows if r["label"] == "negative")
        assert neg == 113, f"Expected 113 negative, got {neg}"


# ---------------------------------------------------------------------------
# 7. CWE / category values are valid
# ---------------------------------------------------------------------------

class TestCWECategory:
    def test_positive_cwe_starts_with_cwe(self, all_rows):
        """All positive samples must have CWE starting with 'CWE-'."""
        bad = [r for r in all_rows
               if r["label"] == "positive" and not r.get("cwe", "").startswith("CWE-")]
        assert not bad, f"Positive samples with invalid CWE: {[(r['sample_id'], r['cwe']) for r in bad[:5]]}"

    def test_negative_cwe_is_none(self, all_rows):
        """All negative samples must have CWE == 'NONE'."""
        bad = [r for r in all_rows
               if r["label"] == "negative" and r.get("cwe", "") != "NONE"]
        assert not bad, f"Negative samples with non-NONE CWE: {[(r['sample_id'], r['cwe']) for r in bad[:5]]}"

    def test_negative_category_is_clean(self, all_rows):
        """All negative samples must have category == 'clean'."""
        bad = [r for r in all_rows
               if r["label"] == "negative" and r.get("category", "") != "clean"]
        assert not bad, f"Negative samples with non-clean category: {bad[:5]}"

    def test_positive_category_not_clean(self, all_rows):
        """No positive sample should have category 'clean'."""
        bad = [r for r in all_rows
               if r["label"] == "positive" and r.get("category", "") == "clean"]
        assert not bad, f"Positive samples with category 'clean': {bad[:5]}"

    def test_all_languages_valid(self, all_rows):
        """Every language must be one of the known valid languages."""
        invalid = [r for r in all_rows if r.get("language", "") not in VALID_LANGUAGES]
        assert not invalid, f"Invalid languages: {[(r['sample_id'], r['language']) for r in invalid[:5]]}"


# ---------------------------------------------------------------------------
# 8. Positive / negative counts are correct
# ---------------------------------------------------------------------------

class TestCounts:
    def test_total_is_500(self, all_rows):
        assert len(all_rows) == 500

    def test_category_cwe89(self, all_rows):
        cnt = sum(1 for r in all_rows if r["category"] == "cwe89")
        assert cnt == 55, f"cwe89: expected 55, got {cnt}"

    def test_category_cwe79(self, all_rows):
        cnt = sum(1 for r in all_rows if r["category"] == "cwe79")
        assert cnt == 55

    def test_category_cwe798(self, all_rows):
        cnt = sum(1 for r in all_rows if r["category"] == "cwe798")
        assert cnt == 55

    def test_category_cwe78(self, all_rows):
        cnt = sum(1 for r in all_rows if r["category"] == "cwe78")
        assert cnt == 55

    def test_category_cwe22(self, all_rows):
        cnt = sum(1 for r in all_rows if r["category"] == "cwe22")
        assert cnt == 55

    def test_category_cwe347(self, all_rows):
        cnt = sum(1 for r in all_rows if r["category"] == "cwe347")
        assert cnt == 45

    def test_category_cwe256(self, all_rows):
        cnt = sum(1 for r in all_rows if r["category"] == "cwe256")
        assert cnt == 30

    def test_category_hallucinated_api(self, all_rows):
        cnt = sum(1 for r in all_rows if r["category"] == "hallucinated_api")
        assert cnt == 23

    def test_category_hallucinated_pkg(self, all_rows):
        cnt = sum(1 for r in all_rows if r["category"] == "hallucinated_pkg")
        assert cnt == 14

    def test_category_clean(self, all_rows):
        cnt = sum(1 for r in all_rows if r["category"] == "clean")
        assert cnt == 113


# ---------------------------------------------------------------------------
# 9. Duplicate detection is deterministic
# ---------------------------------------------------------------------------

class TestDuplicates:
    def test_duplicate_sha256_count_is_zero(self, all_rows):
        """No duplicate SHA-256 in metadata."""
        sha_counter = Counter(r["sha256"] for r in all_rows)
        dups = {k: v for k, v in sha_counter.items() if v > 1}
        assert len(dups) == 0

    def test_duplicate_id_count_is_known(self, all_rows):
        """
        108 duplicate sample_id groups are the documented known state.
        If this changes, investigation is needed.
        """
        id_counter = Counter(r["sample_id"] for r in all_rows)
        dup_count = sum(1 for v in id_counter.values() if v > 1)
        assert dup_count == 108, (
            f"Duplicate sample_id group count changed: expected 108, got {dup_count}. "
            "If dataset was updated, re-audit and update this test."
        )

    def test_duplicate_fp_count_is_known(self, all_rows):
        """16 duplicate file_path entries is the documented known state."""
        fp_counter = Counter(r["file_path"] for r in all_rows)
        dup_count = sum(1 for v in fp_counter.values() if v > 1)
        assert dup_count == 16, (
            f"Duplicate file_path count changed: expected 16, got {dup_count}."
        )


# ---------------------------------------------------------------------------
# 10. Dataset ordering is deterministic
# ---------------------------------------------------------------------------

class TestOrdering:
    def test_loader_ordering_is_stable(self, loader):
        """Calling get_samples() twice must return the same order."""
        s1 = loader.get_samples()
        s2 = loader.get_samples()
        assert [r["file_path"] for r in s1] == [r["file_path"] for r in s2]

    def test_loader_ordering_is_sorted(self, loader):
        """Samples must be sorted by (sample_id, file_path)."""
        samples = loader.get_samples()
        keys = [(r["sample_id"], r["file_path"]) for r in samples]
        assert keys == sorted(keys), "Samples are not in deterministic sorted order"


# ---------------------------------------------------------------------------
# 11. Loader filtering works
# ---------------------------------------------------------------------------

class TestLoaderFiltering:
    def test_filter_by_label_positive(self, loader):
        pos = loader.get_samples(label="positive")
        assert all(r["label"] == "positive" for r in pos)
        assert len(pos) == 387

    def test_filter_by_label_negative(self, loader):
        neg = loader.get_samples(label="negative")
        assert all(r["label"] == "negative" for r in neg)
        assert len(neg) == 113

    def test_filter_by_cwe(self, loader):
        cwe89 = loader.get_samples(cwe="CWE-89")
        assert all(r["cwe"] == "CWE-89" for r in cwe89)
        assert len(cwe89) == 55

    def test_filter_by_category(self, loader):
        clean = loader.get_samples(category="clean")
        assert all(r["category"] == "clean" for r in clean)
        assert len(clean) == 113

    def test_filter_by_language(self, loader):
        py = loader.get_samples(language="python")
        assert all(r["language"] == "python" for r in py)
        assert len(py) == 75

    def test_filter_combined(self, loader):
        pos_py = loader.get_samples(label="positive", language="python")
        assert all(r["label"] == "positive" and r["language"] == "python" for r in pos_py)

    def test_filter_no_match_returns_empty(self, loader):
        result = loader.get_samples(language="cobol")
        assert result == []

    def test_filter_returns_copies(self, loader):
        """Mutating a returned record should not affect internal cache."""
        s1 = loader.get_samples()
        original_id = s1[0]["sample_id"]
        s1[0]["sample_id"] = "MUTATED"
        s2 = loader.get_samples()
        assert s2[0]["sample_id"] == original_id


# ---------------------------------------------------------------------------
# 12. Original dataset files are not modified
# ---------------------------------------------------------------------------

class TestImmutability:
    def test_metadata_csv_sha256_unchanged(self):
        """metadata.csv SHA-256 must match the documented manifest hash."""
        expected_sha = "263415aff6f7de922e84c373b488fe212f8d9d9fb7bd286e812ba165996dc344"
        h = hashlib.sha256(METADATA_CSV.read_bytes()).hexdigest()
        assert h == expected_sha, (
            f"metadata.csv has changed!\n"
            f"  Expected : {expected_sha}\n"
            f"  Actual   : {h}\n"
            "If this is intentional, update dataset_b_config.json and MANIFEST.json."
        )

    def test_loader_does_not_write_files(self, loader, tmp_path):
        """DatasetBLoader must not write any files during get_samples()."""
        # Record mtime of metadata.csv before and after
        mtime_before = METADATA_CSV.stat().st_mtime
        _ = loader.get_samples()
        mtime_after = METADATA_CSV.stat().st_mtime
        assert mtime_before == mtime_after, "metadata.csv was modified by loader!"


# ---------------------------------------------------------------------------
# Run directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-v"],
        cwd=str(_REPO_ROOT),
    )
    sys.exit(result.returncode)
