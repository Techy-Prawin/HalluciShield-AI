#!/usr/bin/env python3
"""
Dataset B Validator - HalluciShield AI Research
================================================
Deterministically validates Dataset B integrity and reproducibility.

Usage:
    python validate_dataset_b.py [--metadata-csv PATH] [--files-root PATH]

Exit codes:
    0  -- all validations passed (warnings may exist)
    1  -- structural error(s) detected
"""

import argparse
import csv
import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

_THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = _THIS_DIR.parents[1]

METADATA_CSV_DEFAULT = REPO_ROOT / "dataset" / "dataset-b" / "metadata.csv"
DATASET_FILES_ROOT_DEFAULT = REPO_ROOT / "dataset" / "dataset" / "dataset-b"

VALID_LABELS = {"positive", "negative"}
REQUIRED_FIELDS = [
    "sample_id", "language", "cwe", "category", "label",
    "generator_model", "generation_prompt", "ground_truth",
    "file_path", "sha256", "generator_provider",
]
EXPECTED_FIELDS = [
    "temperature", "top_p", "max_tokens", "prompt_version", "timestamp",
    "generation_method", "dataset_version", "vulnerability_type",
    "severity", "description", "expected_detection", "expected_patch_types",
]


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_csv(path: Path) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def check_required_fields(rows):
    errors, warnings = [], []
    for r in rows:
        sid = r.get("sample_id", "<unknown>")
        for f in REQUIRED_FIELDS:
            if f not in r or not str(r.get(f, "")).strip():
                errors.append(f"  [{sid}] missing required field: {f!r}")
        for f in EXPECTED_FIELDS:
            if f not in r or not str(r.get(f, "")).strip():
                warnings.append(f"  [{sid}] optional field empty/missing: {f!r}")
    return errors, warnings


def check_labels(rows):
    return [f"  [{r.get('sample_id')}] invalid label: {r.get('label')!r}"
            for r in rows if r.get("label") not in VALID_LABELS]


def check_cwe_category(rows):
    errors = []
    for r in rows:
        sid = r.get("sample_id", "<unknown>")
        label = r.get("label", "")
        cwe = r.get("cwe", "")
        cat = r.get("category", "")
        if label == "positive":
            if not cwe.startswith("CWE-"):
                errors.append(f"  [{sid}] positive sample has invalid CWE: {cwe!r}")
            if cat == "clean":
                errors.append(f"  [{sid}] positive sample has category 'clean'")
        elif label == "negative":
            if cwe != "NONE":
                errors.append(f"  [{sid}] negative sample has non-NONE CWE: {cwe!r}")
            if cat != "clean":
                errors.append(f"  [{sid}] negative sample has non-clean category: {cat!r}")
    return errors


def check_duplicate_ids(rows):
    id_counter = Counter(r.get("sample_id", "") for r in rows)
    dup_groups = {k: v for k, v in id_counter.items() if v > 1}
    lines = []
    for sid, cnt in sorted(dup_groups.items()):
        fps = [r["file_path"] for r in rows if r.get("sample_id") == sid]
        lines.append(f"  [{sid}] x{cnt} -> {fps}")
    return lines, len(dup_groups)


def check_duplicate_file_paths(rows):
    fp_counter = Counter(r.get("file_path", "") for r in rows)
    dup_fps = {k: v for k, v in fp_counter.items() if v > 1}
    lines = [f"  {fp!r} appears {cnt}x" for fp, cnt in sorted(dup_fps.items())]
    return lines, len(dup_fps)


def check_duplicate_sha256(rows):
    sha_counter = Counter(r.get("sha256", "") for r in rows)
    dup_shas = {k: v for k, v in sha_counter.items() if v > 1}
    lines = []
    for sha, cnt in sorted(dup_shas.items()):
        sids = [r["sample_id"] for r in rows if r.get("sha256") == sha]
        lines.append(f"  {sha[:16]}... duplicated {cnt}x -> {sids}")
    return lines, len(dup_shas)


def check_file_existence(rows, files_root: Path):
    missing = []
    for r in rows:
        fp = files_root / r["file_path"].replace("/", os.sep)
        if not fp.exists():
            missing.append(f"  [{r.get('sample_id')}] {r['file_path']}")
    return missing, len(missing)


def check_sha256_integrity(rows, files_root: Path):
    errors, warnings = [], []
    mismatches = 0
    for r in rows:
        fp = files_root / r["file_path"].replace("/", os.sep)
        if not fp.exists():
            warnings.append(f"  [{r.get('sample_id')}] cannot verify hash - file missing")
            continue
        actual = sha256_of_file(fp)
        expected = r.get("sha256", "").lower()
        if actual != expected:
            errors.append(
                f"  [{r.get('sample_id')}] hash mismatch\n"
                f"      metadata: {expected}\n"
                f"      on-disk : {actual}"
            )
            mismatches += 1
    return errors, warnings, mismatches


def check_orphan_files(rows, files_root: Path):
    metadata_fps = {r["file_path"].replace("/", os.sep) for r in rows}
    orphans = []
    skip_names = {"metadata.csv", "metadata.json", "README.md"}
    for dirpath, _, filenames in os.walk(files_root):
        for fn in filenames:
            if fn in skip_names:
                continue
            full = Path(dirpath) / fn
            rel = str(full.relative_to(files_root))
            if rel not in metadata_fps:
                orphans.append(f"  {rel}")
    return orphans, len(orphans)


def section(title):
    print(f"\n{'='*65}")
    print(f"  {title}")
    print(f"{'='*65}")


def passed_result(ok, msg=""):
    icon = "PASS" if ok else "FAIL"
    print(f"  [{icon}]  {msg}")


def parse_args():
    p = argparse.ArgumentParser(description="Dataset B Validator")
    p.add_argument("--metadata-csv", type=Path, default=METADATA_CSV_DEFAULT)
    p.add_argument("--files-root", type=Path, default=DATASET_FILES_ROOT_DEFAULT)
    p.add_argument("--no-hash-check", action="store_true")
    p.add_argument("--strict", action="store_true", help="Treat warnings as errors")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    print("=" * 65)
    print("  HalluciShield -- Dataset B Validator")
    print("=" * 65)
    print(f"  Metadata CSV : {args.metadata_csv}")
    print(f"  Files root   : {args.files_root}")

    section("1. Loading Metadata")
    if not args.metadata_csv.exists():
        print(f"  ERROR: metadata.csv not found at {args.metadata_csv}")
        return 1

    rows = load_csv(args.metadata_csv)
    print(f"  Loaded {len(rows)} rows from metadata.csv")

    section("2. Distribution Summary")
    label_dist = Counter(r.get("label", "") for r in rows)
    cwe_dist = Counter(r.get("cwe", "") for r in rows)
    cat_dist = Counter(r.get("category", "") for r in rows)
    lang_dist = Counter(r.get("language", "") for r in rows)
    model_dist = Counter(r.get("generator_model", "") for r in rows)

    print(f"  Total samples : {len(rows)}")
    print(f"  Positive      : {label_dist.get('positive', 0)}")
    print(f"  Negative      : {label_dist.get('negative', 0)}")

    print("\n  Category distribution:")
    for cat, cnt in sorted(cat_dist.items()):
        print(f"    {cat:<24} {cnt}")

    print("\n  CWE distribution:")
    for cwe, cnt in sorted(cwe_dist.items()):
        print(f"    {cwe:<14} {cnt}")

    print("\n  Language distribution:")
    for lang, cnt in sorted(lang_dist.items()):
        print(f"    {lang:<16} {cnt}")

    print("\n  Generator model:")
    for model, cnt in sorted(model_dist.items()):
        print(f"    {model:<32} {cnt}")

    all_errors: List[str] = []
    all_warnings: List[str] = []
    structural_fail = False

    section("3. Required Metadata Fields")
    fe, fw = check_required_fields(rows)
    if fe:
        structural_fail = True
        all_errors.extend(fe)
        passed_result(False, f"{len(fe)} required field error(s)")
        for e in fe[:10]:
            print(e)
    else:
        passed_result(True, "All required fields present")
    if fw:
        all_warnings.extend(fw)
        print(f"  Warnings: {len(fw)} optional field(s) missing/empty")

    section("4. Label Validation")
    le = check_labels(rows)
    if le:
        structural_fail = True
        all_errors.extend(le)
        passed_result(False, f"{len(le)} invalid label(s)")
        for e in le[:10]:
            print(e)
    else:
        passed_result(True, "All labels valid")

    section("5. CWE / Category Validation")
    ce = check_cwe_category(rows)
    if ce:
        structural_fail = True
        all_errors.extend(ce)
        passed_result(False, f"{len(ce)} CWE/category error(s)")
        for e in ce[:10]:
            print(e)
    else:
        passed_result(True, "All CWE/category mappings valid")

    section("6. Duplicate Sample IDs")
    die, dic = check_duplicate_ids(rows)
    if die:
        all_warnings.extend(die)
        passed_result(False, f"{dic} duplicate sample_id group(s) -- see audit report")
        for e in die[:10]:
            print(e)
        if len(die) > 10:
            print(f"  ... and {len(die) - 10} more")
    else:
        passed_result(True, "All sample IDs unique")

    section("7. Duplicate File Paths")
    dfe, dfc = check_duplicate_file_paths(rows)
    if dfe:
        structural_fail = True
        all_errors.extend(dfe)
        passed_result(False, f"{dfc} duplicate file_path(s) in metadata")
        for e in dfe[:10]:
            print(e)
    else:
        passed_result(True, "All file paths unique in metadata")

    section("8. Duplicate SHA-256 (metadata)")
    dse, dsc = check_duplicate_sha256(rows)
    if dse:
        structural_fail = True
        all_errors.extend(dse)
        passed_result(False, f"{dsc} duplicate SHA-256 group(s)")
        for e in dse[:5]:
            print(e)
    else:
        passed_result(True, "No duplicate SHA-256 hashes in metadata")

    section("9. File Existence")
    mf, mc = check_file_existence(rows, args.files_root)
    if mf:
        structural_fail = True
        all_errors.extend(mf)
        passed_result(False, f"{mc} missing file(s) on disk")
        for e in mf[:10]:
            print(e)
        if len(mf) > 10:
            print(f"  ... and {len(mf) - 10} more")
    else:
        passed_result(True, f"All {len(rows)} referenced files exist on disk")

    section("10. SHA-256 Integrity")
    if args.no_hash_check:
        print("  SKIPPED (--no-hash-check)")
    else:
        she, shw, shm = check_sha256_integrity(rows, args.files_root)
        if she:
            all_warnings.extend(she)
            passed_result(False, f"{shm} SHA-256 mismatch(es) (metadata != on-disk hash)")
            for e in she[:5]:
                print(e)
            if len(she) > 5:
                print(f"  ... and {len(she) - 5} more")
        else:
            passed_result(True, "All on-disk SHA-256 hashes match metadata")
        all_warnings.extend(shw)

    section("11. Orphan Files")
    orf, orc = check_orphan_files(rows, args.files_root)
    if orf:
        all_warnings.append(f"{orc} orphan file(s) on disk not in metadata")
        print(f"  WARNING: {orc} file(s) on disk not referenced in metadata")
        for e in orf[:10]:
            print(e)
        if len(orf) > 10:
            print(f"  ... and {len(orf) - 10} more")
    else:
        passed_result(True, "No orphan files")

    section("FINAL SUMMARY")
    print(f"  Total samples in metadata  : {len(rows)}")
    print(f"  Positive samples           : {label_dist.get('positive', 0)}")
    print(f"  Negative samples           : {label_dist.get('negative', 0)}")
    print(f"  Duplicate sample_id groups : {dic}")
    print(f"  Duplicate file_paths       : {dfc}")
    print(f"  Missing files on disk      : {mc}")
    print(f"  Orphan files on disk       : {orc}")
    print(f"  Structural errors          : {len(all_errors)}")
    print(f"  Warnings                   : {len(all_warnings)}")

    if args.strict and all_warnings:
        structural_fail = True

    if structural_fail:
        print("\n  STATUS: FAIL -- structural error(s) detected")
        return 1
    print("\n  STATUS: PASS")
    if all_warnings:
        print(f"  (with {len(all_warnings)} warning(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
