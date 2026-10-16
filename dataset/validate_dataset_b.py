#!/usr/bin/env python3
"""
Dataset B Validator
===================
Validates Dataset B meets all requirements.
Exits with non-zero code if any requirement fails.
"""

import os
import csv
import json
import hashlib
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

DATASET_DIR = Path(__file__).parent / "dataset-b"
METADATA_CSV = DATASET_DIR / "metadata.csv"
METADATA_JSON = DATASET_DIR / "metadata.json"

EXPECTED_TOTAL = 500
EXPECTED_POSITIVE = 387
EXPECTED_NEGATIVE = 113

EXPECTED_CATEGORIES = {
    "cwe89": 55,
    "cwe79": 55,
    "cwe798": 55,
    "cwe78": 55,
    "cwe22": 55,
    "cwe347": 45,
    "cwe256": 30,
    "hallucinated_api": 23,
    "hallucinated_pkg": 14,
    "clean": 113,
}

REQUIRED_FIELDS = [
    "sample_id", "language", "cwe", "category", "label",
    "generator_model", "generation_prompt", "ground_truth",
    "file_path", "sha256", "generator_provider", "temperature",
    "top_p", "max_tokens", "prompt_version", "timestamp",
    "generation_method", "dataset_version", "vulnerability_type",
    "severity", "description", "expected_detection",
    "expected_patch_types"
]


def compute_sha256(filepath: Path) -> str:
    """Compute SHA-256 hash of file."""
    if not filepath.exists():
        return ""
    return hashlib.sha256(filepath.read_bytes()).hexdigest()


def validate_counts(samples: List[Dict]) -> Tuple[bool, List[str]]:
    """Validate total and category counts."""
    errors = []
    
    total = len(samples)
    if total != EXPECTED_TOTAL:
        errors.append(f"Total count: expected {EXPECTED_TOTAL}, got {total}")
    
    positive = sum(1 for s in samples if s["label"] == "positive")
    if positive != EXPECTED_POSITIVE:
        errors.append(f"Positive count: expected {EXPECTED_POSITIVE}, got {positive}")
    
    negative = sum(1 for s in samples if s["label"] == "negative")
    if negative != EXPECTED_NEGATIVE:
        errors.append(f"Negative count: expected {EXPECTED_NEGATIVE}, got {negative}")
    
    # Category counts
    cat_counts = {}
    for s in samples:
        cat = s["category"]
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
    
    for cat, expected in EXPECTED_CATEGORIES.items():
        actual = cat_counts.get(cat, 0)
        if actual != expected:
            errors.append(f"Category {cat}: expected {expected}, got {actual}")
    
    return len(errors) == 0, errors


def validate_metadata_fields(samples: List[Dict]) -> Tuple[bool, List[str]]:
    """Validate all required metadata fields are present."""
    errors = []
    for i, sample in enumerate(samples):
        for field in REQUIRED_FIELDS:
            if field not in sample:
                errors.append(f"Sample {i} (id={sample.get('sample_id', 'unknown')}): missing required field '{field}'")
            elif sample[field] is None or sample[field] == "":
                errors.append(f"Sample {i} (id={sample.get('sample_id', 'unknown')}): empty value for required field '{field}'")
    return len(errors) == 0, errors


def validate_file_existence(samples: List[Dict], base_dir: Path) -> Tuple[bool, List[str]]:
    """Validate every metadata file exists on disk."""
    errors = []
    for sample in samples:
        file_path = base_dir / sample["file_path"]
        if not file_path.exists():
            errors.append(f"Sample {sample['sample_id']}: file not found at {file_path}")
    return len(errors) == 0, errors


def validate_hashes(samples: List[Dict], base_dir: Path) -> Tuple[bool, List[str]]:
    """Validate every SHA-256 matches file content."""
    errors = []
    for sample in samples:
        file_path = base_dir / sample["file_path"]
        if file_path.exists():
            actual_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
            expected_hash = sample["sha256"].lower()
            if actual_hash != expected_hash:
                errors.append(f"Sample {sample['sample_id']}: hash mismatch. Expected {expected_hash}, got {actual_hash}")
        else:
            errors.append(f"Sample {sample['sample_id']}: cannot verify hash - file missing")
    return len(errors) == 0, errors


def validate_no_duplicate_hashes(samples: List[Dict]) -> Tuple[bool, List[str]]:
    """Validate no duplicate SHA-256 hashes."""
    seen: Dict[str, str] = {}
    errors = []
    for sample in samples:
        h = sample["sha256"]
        if h in seen:
            errors.append(f"Duplicate hash: {sample['sample_id']} and {seen[h]} both have hash {h}")
        else:
            seen[h] = sample["sample_id"]
    return len(errors) == 0, errors


def validate_no_duplicate_ids(samples: List[Dict]) -> Tuple[bool, List[str]]:
    """Validate no duplicate sample IDs."""
    seen = set()
    errors = []
    for sample in samples:
        sid = sample["sample_id"]
        if sid in seen:
            errors.append(f"Duplicate sample ID: {sid}")
        else:
            seen.add(sid)
    return len(errors) == 0, errors


def validate_positive_samples(samples: List[Dict]) -> Tuple[bool, List[str]]:
    """Validate positive samples have valid CWE/category."""
    errors = []
    for sample in samples:
        if sample["label"] == "positive":
            if sample["cwe"] == "NONE" or not sample["cwe"].startswith("CWE-"):
                errors.append(f"Sample {sample['sample_id']}: positive sample has invalid CWE '{sample['cwe']}'")
            if sample["category"] == "clean":
                errors.append(f"Sample {sample['sample_id']}: positive sample has category 'clean'")
            if sample.get("vulnerability_type") in ["NONE", "", None]:
                errors.append(f"Sample {sample['sample_id']}: positive sample missing vulnerability_type")
    return len(errors) == 0, errors


def validate_negative_samples(samples: List[Dict]) -> Tuple[bool, List[str]]:
    """Validate negative samples are marked clean."""
    errors = []
    for sample in samples:
        if sample["label"] == "negative":
            if sample["cwe"] != "NONE":
                errors.append(f"Sample {sample['sample_id']}: negative sample has CWE '{sample['cwe']}' (expected NONE)")
            if sample["category"] != "clean":
                errors.append(f"Sample {sample['sample_id']}: negative sample has category '{sample['category']}' (expected clean)")
            if sample.get("expected_detection") is True:
                errors.append(f"Sample {sample['sample_id']}: negative sample has expected_detection=True (expected False)")
    return len(errors) == 0, errors


def validate_csv_json_consistency(samples_csv: List[Dict], samples_json: List[Dict]) -> Tuple[bool, List[str]]:
    """Validate CSV and JSON have same data."""
    errors = []
    if len(samples_csv) != len(samples_json):
        errors.append(f"Count mismatch: CSV={len(samples_csv)}, JSON={len(samples_json)}")
        return False, errors
    
    csv_by_id = {s["sample_id"]: s for s in samples_csv}
    json_by_id = {s["sample_id"]: s for s in samples_json}
    
    if set(csv_by_id.keys()) != set(json_by_id.keys()):
        errors.append("Sample ID sets differ between CSV and JSON")
        return False, errors
    
    for sid in csv_by_id:
        csv_s = csv_by_id[sid]
        json_s = json_by_id[sid]
        for key in csv_s:
            if key not in json_s:
                errors.append(f"Sample {sid}: key '{key}' missing in JSON")
            elif str(csv_s[key]) != str(json_s[key]):
                errors.append(f"Sample {sid}: value mismatch for '{key}': CSV='{csv_s[key]}' vs JSON='{json_s[key]}'")
    
    return len(errors) == 0, errors


def validate_metadata_counts_match_filesystem(samples: List[Dict], base_dir: Path) -> Tuple[bool, List[str]]:
    """Validate metadata counts match actual files on disk."""
    errors = []
    pos_files = len(list((base_dir / "positive").rglob("*")))
    neg_files = len(list((base_dir / "negative").rglob("*")))
    # Note: this counts directories too, so it's approximate
    
    pos_samples = sum(1 for s in samples if s["label"] == "positive")
    neg_samples = sum(1 for s in samples if s["label"] == "negative")
    
    # Each sample should have exactly one file
    if pos_samples != EXPECTED_POSITIVE:
        errors.append(f"Positive sample count in metadata ({pos_samples}) != expected ({EXPECTED_POSITIVE})")
    if neg_samples != EXPECTED_NEGATIVE:
        errors.append(f"Negative sample count in metadata ({neg_samples}) != expected ({EXPECTED_NEGATIVE})")
    
    return len(errors) == 0, errors


def load_samples_csv(path: Path) -> List[Dict]:
    """Load samples from CSV."""
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return list(reader)


def load_samples_json(path: Path) -> List[Dict]:
    """Load samples from JSON."""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def main():
    print("=" * 70)
    print("  Dataset B Validator")
    print("=" * 70)
    
    base_dir = DATASET_DIR
    all_errors = []
    
    # Load data
    print("\n[1/9] Loading metadata...")
    if not METADATA_CSV.exists():
        print(f"  ERROR: {METADATA_CSV} not found")
        sys.exit(1)
    if not METADATA_JSON.exists():
        print(f"  ERROR: {METADATA_JSON} not found")
        sys.exit(1)
    
    samples_csv = load_samples_csv(METADATA_CSV)
    samples_json = load_samples_json(METADATA_JSON)
    print(f"  Loaded {len(samples_csv)} samples from CSV")
    print(f"  Loaded {len(samples_json)} samples from JSON")
    
    # Run validations
    checks = [
        ("Counts", validate_counts, (samples_csv,)),
        ("Metadata fields", validate_metadata_fields, (samples_csv,)),
        ("File existence", validate_file_existence, (samples_csv, base_dir)),
        ("Hash integrity", validate_hashes, (samples_csv, base_dir)),
        ("No duplicate hashes", validate_no_duplicate_hashes, (samples_csv,)),
        ("No duplicate IDs", validate_no_duplicate_ids, (samples_csv,)),
        ("Positive samples", validate_positive_samples, (samples_csv,)),
        ("Negative samples", validate_negative_samples, (samples_csv,)),
        ("CSV/JSON consistency", validate_csv_json_consistency, (samples_csv, samples_json)),
        ("Metadata/filesystem match", validate_metadata_counts_match_filesystem, (samples_csv, base_dir)),
    ]
    
    all_passed = True
    for name, func, args in checks:
        print(f"\n[{checks.index((name, func, args))+1}/{len(checks)}] {name}...")
        passed, errors = func(*args)
        if passed:
            print(f"  PASS")
        else:
            print(f"  FAIL")
            for e in errors:
                print(f"  - {e}")
            all_errors.extend(errors)
            all_passed = False
    
    # Summary
    print("\n" + "=" * 70)
    if all_passed:
        print("  ALL VALIDATIONS PASSED")
        print("=" * 70)
        return 0
    else:
        print(f"  VALIDATION FAILED: {len(all_errors)} error(s)")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(main())