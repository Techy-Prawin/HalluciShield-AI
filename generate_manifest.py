#!/usr/bin/env python3
"""Generate Dataset B MANIFEST.json with authoritative disk hashes and record_ids."""

import csv
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

# --- Configuration ---
METADATA_CSV = Path(r"C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset-b\metadata.csv")
DATASET_DIR = Path(r"C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset\dataset-b")
WEB_DIR = Path(r"C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset-b")

# --- Load metadata ---
with open(str(METADATA_CSV), 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    samples = list(reader)

print(f"Loading {len(samples)} samples...")

# --- Determine actual file locations ---
sample_info = []
for s in samples:
    fp_actual = DATASET_DIR / s['file_path']
    fp_web = WEB_DIR / s['file_path']
    
    if fp_actual.exists():
        actual_path = fp_actual
        disk_dir = DATASET_DIR
    elif fp_web.exists():
        actual_path = fp_web
        disk_dir = WEB_DIR
    else:
        actual_path = None
        disk_dir = None
    
    # Compute disk SHA-256
    disk_sha256 = "MISSING"
    if actual_path and actual_path.exists():
        disk_sha256 = hashlib.sha256(actual_path.read_bytes()).hexdigest().lower()
    
    # Compute metadata SHA-256 (from metadata)
    metadata_sha256 = s['sha256'].lower()
    
    # Compute record_id = sha256(relative_file_path + ':' + disk_sha256)
    path_for_hash = s['file_path'] + ":" + disk_sha256
    record_id = hashlib.sha256(path_for_hash.encode('utf-8')).hexdigest()
    
    sample_info.append({
        'sample_id': s['sample_id'],
        'file_path': s['file_path'],
        'label': s['label'],
        'cwe': s['cwe'],
        'category': s['category'],
        'language': s['language'],
        'expected_detection': s['expected_detection'],
        'disk_sha256': disk_sha256,
        'metadata_sha256': metadata_sha256,
        'record_id': record_id,
        'actual_path': str(actual_path) if actual_path else None,
        'exists': actual_path is not None and actual_path.exists(),
    })

# --- Build manifest ---
manifest = {
    'manifest_format_version': 'v1.0',
    'dataset_name': 'Dataset B - HalluciShield AI',
    'dataset_version': 'v1.0',
    'created_at': datetime.utcnow().isoformat() + 'Z',
    'total_samples': len(sample_info),
    'positive_samples': sum(1 for s in sample_info if s['label'] == 'positive'),
    'negative_samples': sum(1 for s in sample_info if s['label'] == 'negative'),
    'unique_sample_ids': len(set(s['sample_id'] for s in sample_info)),
    'duplicate_sample_id_groups': len(set(s['sample_id'] for s in sample_info if sum(1 for t in sample_info if t['sample_id'] == s) > 1)),
    'files_found_on_disk': sum(1 for s in sample_info if s['exists']),
    'files_root_path': str(DATASET_DIR),
    'notes': 'Manifest contains authoritative disk SHA-256 hashes and deterministic record_ids. '
             'Original sample_id values are preserved unchanged. '
             '500/500 metadata SHA-256 hashes do not match disk hashes due to path discrepancy '
             '(metadata references dataset/dataset-b/, actual files at dataset/dataset/dataset-b/). '
             'Use record_id = sha256(relative_file_path + ":" + disk_sha256) as experiment unique key.',
    'samples': sample_info
}

# Write manifest
manifest_path = Path(r"C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset-b\MANIFEST.json")
with open(str(manifest_path), 'w', encoding='utf-8') as f:
    json.dump(manifest, f, indent=2)

print(f"\nManifest written to {manifest_path}")
print(f"Total samples: {len(sample_info)}")
print(f"Files on disk: {sum(1 for s in sample_info if s['exists'])}")
unique_disk = len(set(s['disk_sha256'] for s in sample_info if s['disk_sha256'] != 'MISSING'))
print(f"Unique disk SHA-256: {unique_disk}")

hash_matches = sum(1 for s in sample_info if s['disk_sha256'] != 'MISSING' and s['disk_sha256'] == s['metadata_sha256'])
print(f"Metadata/disk SHA-256 matches: {hash_matches}/{len(sample_info)}")

# Show a few samples
print("\nFirst 5 samples in manifest:")
for s in sample_info[:5]:
    print(f"  {s['sample_id']}: path={s['file_path'][:40]}... disk={s['disk_sha256'][:16]}... record_id={s['record_id'][:16]}...")