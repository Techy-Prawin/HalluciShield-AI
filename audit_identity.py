#!/usr/bin/env python3
"""
Phase 5.6: Dataset B Identity Audit - 17 Duplicated record_id Groups
"""
import sys, json, hashlib
from pathlib import Path
from collections import Counter

_REPO_ROOT = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / 'ai-engine'))

from evaluation.dataset_b.dataset_loader import DatasetBLoader
from evaluation.dataset_b.evaluator import ExecutionStatus, load_all_samples_info

print("=" * 70)
print("PHASE 5.6: DATASET B IDENTITY AUDIT")
print("=" * 70)

# Load all samples
all_samples = load_all_samples_info()
print(f"Total samples: {len(all_samples)}")

# Group by record_id
record_groups = {}
for s in all_samples:
    rid = s.get('record_id', 'MISSING')
    if rid not in record_groups:
        record_groups[rid] = []
    record_groups[rid].append(s)

# Find duplicated record_ids
duplicated_rids = {rid: recs for rid, recs in record_groups.items() if len(recs) > 1}
print(f"\nDuplicated record_ids: {len(duplicated_rids)}")

# Analyze each duplicated group
print("\n" + "=" * 70)
print("17 DUPLICATED record_id GROUPS ANALYSIS")
print("=" * 70)

exact_duplicates = 0
distinct_content = 0
unresolved = 0

for rid, recs in sorted(duplicated_rids.items()):
    print(f"\n--- record_id = {rid} (count: {len(recs)}) ---")
    
    # Collect attributes
    sample_ids = [r.get('sample_id', 'MISSING') for r in recs]
    file_paths = [r.get('file_path', 'MISSING') for r in recs]
    cwe_vals = [r.get('cwe', 'MISSING') for r in recs]
    lang_vals = [r.get('language', 'MISSING') for r in recs]
    cat_vals = [r.get('category', 'MISSING') for r in recs]
    
    # Disk SHA-256 and file sizes
    disk_hashes = []
    file_sizes = []
    for r in recs:
        loader = DatasetBLoader(
            metadata_csv=r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset-b\metadata.csv',
            files_root=r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset\dataset-b'
        )
        fp = loader.get_file_path(r)
        try:
            if fp.exists():
                ds = hashlib.sha256(open(fp, 'rb').read()).hexdigest()
                disk_hashes.append(ds)
                file_sizes.append(str(fp.stat().st_size) if fp.exists() else 'MISSING')
            else:
                disk_hashes.append('FILE_MISSING')
                file_sizes.append('FILE_MISSING')
        except Exception as e:
            disk_hashes.append('ERROR')
            file_sizes.append('ERROR')
    
    # Check if files are byte-identical
    byte_identical = True
    if len(file_sizes) > 1:
        with open(file_sizes[0] if file_sizes[0] != 'FILE_MISSING' else '', 'rb') as f:
            base_hash = hashlib.sha256(f.read()).hexdigest()
        for fs in file_sizes[1:]:
            if fs != 'FILE_MISSING' and fs != 'ERROR':
                try:
                    with open(fs, 'rb') as f:
                        comp_hash = hashlib.sha256(f.read()).hexdigest()
                    if comp_hash != base_hash:
                        byte_identical = False
                except:
                    byte_identical = False
    
    # Determine classification
    is_exact = (len(recs) == len(set(file_paths)) and byte_identical and len(set(cwe_vals)) == 1 and len(set(lang_vals)) == 1)
    is_distinct = (len(set(file_paths)) > 1 or len(set(cwe_vals)) > 1 or len(set(lang_vals)) > 1)
    
    if is_exact:
        classification = "EXACT_DUPLICATE"
        exact_duplicates += 1
    elif is_distinct:
        classification = "DISTINCT_CONTENT"
        distinct_content += 1
    else:
        classification = "UNRESOLVED"
        unresolved += 1
    
    print(f"  sample_ids: {sample_ids}")
    print(f"  file_paths: {file_paths}")
    print(f"  disk_hashes: {disk_hashes[:2]}...")  # first 2
    print(f"  file_sizes: {file_sizes}")
    print(f"  cwe_vals: {cwe_vals}")
    print(f"  lang_vals: {lang_vals}")
    print(f"  byte_identical: {byte_identical}")
    print(f"  classification: {classification}")
    print()

print("\n" + "=" * 70)
print("CLASSIFICATION SUMMARY")
print("=" * 70)
print(f"  EXACT_DUPLICATE:   {exact_duplicates}")
print(f"  DISTINCT_CONTENT:  {distinct_content}")
print(f"  UNRESOLVED:        {unresolved}")
print(f"  Total:             {exact_duplicates + distinct_content + unresolved}")
print("\nExpected: 17 groups")

# Determine experimental unit
print("\n" + "=" * 70)
print("EXPERIMENTAL UNIT DECISION")
print("=" * 70)

total_groups = exact_duplicates + distinct_content + unresolved
if unresolved > 0:
    print("  UNRESOLVED groups detected - need manual review before proceeding")
elif distinct_content > 0 and exact_duplicates > 0:
    print("  Mixed: exact duplicates + distinct content groups")
    print("  -> Use record_id + file_path + config_id as experimental unit")
elif exact_duplicates > 0 and distinct_content == 0:
    print("  All exact duplicates - can use record_id as experimental unit (deduplicated)")
    print("  -> Expected evaluations: 483 unique record_ids (not 500)")
elif distinct_content > 0 and exact_duplicates == 0:
    print("  All distinct content - 500 unique experimental units")
    print("  -> Use full 500 record_ids as experimental unit")
    
print(f"\n  Unique record_ids in full dataset: {len(record_groups)}")
print(f"  Total sample entries: {len(all_samples)}")