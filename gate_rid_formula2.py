import json
import hashlib
from pathlib import Path
from collections import Counter, defaultdict

print("=" * 70)
print("DETERMINING WHAT FORMULA PRODUCES MISMATCHED RECORD_IDS")
print("=" * 70)

manifest_path = Path(r'dataset/dataset-b/MANIFEST.json')
with open(manifest_path) as f:
    manifest = json.load(f)

samples = manifest['samples']
sample_map = {}
for s in samples:
    sample_map[s['sample_id']] = {
        'file_path': s['file_path'],
        'disk_sha256': s['disk_sha256'],
        'record_id_manifest': s['record_id']
    }

raw_path = Path(r'evaluation/results/research/ablation500/raw_results.jsonl')
with open(raw_path) as f:
    raw_lines = f.readlines()

# Known formulas
# F1: sha256(file_path + ':' + disk_sha256)  -- this is the "manifest formula"

# Count F1 matches
f1_matches = 0
for line in raw_lines:
    r = json.loads(line)
    sid = r.get('sample_id', '')
    if sid in sample_map:
        sm = sample_map[sid]
        f1 = hashlib.sha256((sm['file_path'] + ':' + sm['disk_sha256']).encode()).hexdigest()
        if r.get('record_id', '') == f1:
            f1_matches += 1

print(f"F1 (manifest formula sha256(file_path ':' disk_sha256)) matches: {f1_matches} / {len(raw_lines)}")

# For mismatched records (where F1 doesn't match), check F2, F3
mismatch_formula_counts = Counter()
for line in raw_lines:
    r = json.loads(line)
    sid = r.get('sample_id', '')
    raw_rid = r.get('record_id', '')
    
    if sid not in sample_map:
        continue
    
    sm = sample_map[sid]
    
    # F1 already computed above, but we need per-record
    f1 = hashlib.sha256((sm['file_path'] + ':' + sm['disk_sha256']).encode()).hexdigest()
    
    if raw_rid == f1:
        continue  # matches F1, skip
    
    # Try F2: sha256(file_path + disk_sha256) no colon
    f2 = hashlib.sha256((sm['file_path'] + sm['disk_sha256']).encode()).hexdigest()
    if raw_rid == f2:
        mismatch_formula_counts['F2: no-colon'] += 1
        continue
    
    # Try F3: sha256(disk_sha256 + ':' + file_path) reversed
    f3 = hashlib.sha256((sm['disk_sha256'] + ':' + sm['file_path']).encode()).hexdigest()
    if raw_rid == f3:
        mismatch_formula_counts['F3: reversed colon'] += 1
        continue
    
    # Try F4: sha256(file_path) only
    f4 = hashlib.sha256(sm['file_path'].encode()).hexdigest()
    if raw_rid == f4:
        mismatch_formula_counts['F4: file_path only'] += 1
        continue
    
    # Try F5: sha256(disk_sha256) only
    f5 = hashlib.sha256(sm['disk_sha256'].encode()).hexdigest()
    if raw_rid == f5:
        mismatch_formula_counts['F5: disk_sha256 only'] += 1
        continue
    
    # Try F6: sha256(sample_id) only
    f6 = hashlib.sha256(sid.encode()).hexdigest()
    if raw_rid == f6:
        mismatch_formula_counts['F6: sample_id only'] += 1
        continue
    
    mismatch_formula_counts['NO MATCH'] += 1

print("\nFormulas that produce mismatched record_ids:")
for formula, cnt in mismatch_formula_counts.most_common():
    print(f"  {formula}: {cnt} records")

# Also check: how many of the mismatched records have sample_ids that appear in the 
# 108 duplicate sample_id groups from IDENTITY_AUDIT.md?
print(f"\nTotal records analyzed: {sum(mismatch_formula_counts.values())}")
print(f"F1 matches: {f1_matches}")

# Key finding: the 1358 mismatched records - what formula produces their record_ids?
# This will tell us whether the raw_results use a different identity rule