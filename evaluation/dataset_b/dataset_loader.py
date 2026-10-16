#!/usr/bin/env python3
"""
Dataset B Loader - HalluciShield AI Research
=============================================
Provides deterministic, reproducible access to Dataset B samples.

Usage example:
    from evaluation.dataset_b.dataset_loader import DatasetBLoader

    loader = DatasetBLoader()
    all_samples = loader.get_samples()
    positive = loader.get_samples(label="positive")
    sql_inj = loader.get_samples(cwe="CWE-89")
    py_samples = loader.get_samples(language="python")

Rules:
- Stable ordering (sorted by sample_id then file_path, deterministic).
- No random behaviour unless an explicit seed is supplied.
- Does NOT modify any source file.
- Returns copies of records; callers may not mutate the internal cache.
"""

import csv
import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional

_REPO_ROOT = Path(__file__).resolve().parents[2]

METADATA_CSV_DEFAULT = _REPO_ROOT / "dataset" / "dataset-b" / "metadata.csv"
DATASET_FILES_ROOT_DEFAULT = _REPO_ROOT / "dataset" / "dataset" / "dataset-b"

DATASET_VERSION = "v1.0"


class DatasetBLoader:
    """
    Deterministic loader for Dataset B.

    Parameters
    ----------
    metadata_csv : Path
        Path to metadata.csv.
    files_root : Path
        Root directory containing the actual code files.
    """

    def __init__(
        self,
        metadata_csv: Optional[Path] = None,
        files_root: Optional[Path] = None,
    ) -> None:
        self._metadata_csv = Path(metadata_csv or METADATA_CSV_DEFAULT)
        self._files_root = Path(files_root or DATASET_FILES_ROOT_DEFAULT)
        self._rows: Optional[List[Dict]] = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load(self) -> List[Dict]:
        """Load and cache metadata. Returns stable-sorted list."""
        if self._rows is not None:
            return self._rows
        if not self._metadata_csv.exists():
            raise FileNotFoundError(
                f"metadata.csv not found: {self._metadata_csv}"
            )
        with open(self._metadata_csv, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
        # Stable deterministic ordering: sort by (sample_id, file_path)
        rows.sort(key=lambda r: (r.get("sample_id", ""), r.get("file_path", "")))
        self._rows = rows
        return self._rows

    def _copy(self, row: Dict) -> Dict:
        """Return a shallow copy so callers cannot mutate the cache."""
        return dict(row)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_samples(
        self,
        *,
        label: Optional[str] = None,
        cwe: Optional[str] = None,
        category: Optional[str] = None,
        language: Optional[str] = None,
        generator_model: Optional[str] = None,
        split: Optional[str] = None,
    ) -> List[Dict]:
        """
        Return a filtered, deterministically ordered list of sample records.

        All filters are exact-match (case-insensitive for string fields).
        Multiple filters are ANDed.

        Parameters
        ----------
        label          : "positive" | "negative"
        cwe            : e.g. "CWE-89"
        category       : e.g. "cwe89", "clean", "hallucinated_api"
        language       : e.g. "python", "javascript"
        generator_model: e.g. "qwen/qwen3.8-27b"
        split          : "train" | "test" | "val"  (only if split column exists)

        Returns
        -------
        List of dict copies — one per matching sample record.
        """
        rows = self._load()
        result = []
        for r in rows:
            if label is not None and r.get("label", "").lower() != label.lower():
                continue
            if cwe is not None and r.get("cwe", "").upper() != cwe.upper():
                continue
            if category is not None and r.get("category", "").lower() != category.lower():
                continue
            if language is not None and r.get("language", "").lower() != language.lower():
                continue
            if generator_model is not None and r.get("generator_model", "") != generator_model:
                continue
            if split is not None and r.get("split", "") != split:
                continue
            result.append(self._copy(r))
        return result

    def get_file_path(self, sample: Dict) -> Path:
        """Return the absolute path to the code file for a sample record."""
        rel = sample["file_path"].replace("/", os.sep)
        return self._files_root / rel

    def read_code(self, sample: Dict) -> str:
        """Read and return the source code for a sample as a UTF-8 string."""
        fp = self.get_file_path(sample)
        if not fp.exists():
            raise FileNotFoundError(f"Code file missing: {fp}")
        with open(fp, encoding="utf-8", errors="replace") as fh:
            return fh.read()

    def sha256_of_file(self, sample: Dict) -> str:
        """Compute the actual SHA-256 of the on-disk file (deterministic)."""
        fp = self.get_file_path(sample)
        h = hashlib.sha256()
        with open(fp, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def get_unique_sample_ids(self) -> List[str]:
        """Return sorted list of all unique sample IDs in metadata."""
        rows = self._load()
        return sorted(set(r.get("sample_id", "") for r in rows))

    def get_all_file_paths(self) -> List[Path]:
        """Return sorted list of absolute paths for all referenced files."""
        rows = self._load()
        paths = [self.get_file_path(r) for r in rows]
        return sorted(set(paths), key=lambda p: str(p))

    def summary(self) -> Dict:
        """Return a summary dict of dataset statistics."""
        from collections import Counter
        rows = self._load()
        label_dist = Counter(r.get("label", "") for r in rows)
        cwe_dist = Counter(r.get("cwe", "") for r in rows)
        cat_dist = Counter(r.get("category", "") for r in rows)
        lang_dist = Counter(r.get("language", "") for r in rows)
        model_dist = Counter(r.get("generator_model", "") for r in rows)
        return {
            "dataset_version": DATASET_VERSION,
            "total_samples": len(rows),
            "positive_samples": label_dist.get("positive", 0),
            "negative_samples": label_dist.get("negative", 0),
            "unique_sample_ids": len(set(r.get("sample_id", "") for r in rows)),
            "label_distribution": dict(label_dist),
            "cwe_distribution": dict(cwe_dist),
            "category_distribution": dict(cat_dist),
            "language_distribution": dict(lang_dist),
            "generator_model_distribution": dict(model_dist),
            "metadata_csv": str(self._metadata_csv),
            "files_root": str(self._files_root),
        }

    @property
    def metadata_csv(self) -> Path:
        return self._metadata_csv

    @property
    def files_root(self) -> Path:
        return self._files_root
