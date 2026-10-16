import json
import hashlib
from pathlib import Path
from collections import Counter

print("=" * 70)
print("INDEPENDENT VALIDITY GATE AUDIT")
print("=" * 70)

# 1. Raw results enumeration
raw_path = Path(r'evaluation/results/research/ablation500/raw_results.jsonl')
with open(raw_path) as f:
    lines = f.readlines()

total_lines = len(lines)
valid_json = 0
malformed = 0
for line in lines:
    try:
        json.loads(line)
        valid_json += 1
    except json.JSONDecodeError:
        malformed += 1

print(f"\n1. RAW RESULTS (raw_results.jsonl)")
print(f"   Total physical lines: {total_lines}")
print(f"   Valid JSON rows: {valid_json}")
print(f"   Malformed rows: {malformed}")

# 2. Identity verification: record_id = sha256(relative_file_path + ":" + disk_sha256)
# Using manifest
manifest_path = Path(r'dataset/dataset-b/MANIFEST.json')
with open(manifest_path) as f:
    manifest = json.load(f)

samples = manifest['samples']  # 500 records
sample_map = {}
for s in samples:
    sid = s['sample_id']
    file_path = s['file_path']
    disk_sha256 = s['disk_sha256']
    record_id_manifest = s['record_id']
    sample_map[sid] = {
        'file_path': file_path,
        'disk_sha256': disk_sha256,
        'record_id_manifest': record_id_manifest
    }

# Count unique record_ids from manifest formula
manifest_rids = set()
for line in lines:
    r = json.loads(line)
    sid = r.get('sample_id', '')
    if sid in sample_map:
        sm = sample_map[sid]
        rid = hashlib.sha256((sm['file_path'] + ':' + sm['disk_sha256']).encode()).hexdigest()
        manifest_rids.add(rid)

# Also count from raw results' own record_id field
raw_rids = set()
for line in lines:
    r = json.loads(line)
    raw_rids.add(r.get('record_id', ''))

print(f"\n2. IDENTITY VERIFICATION")
print(f"   Unique record_ids from manifest formula: {len(manifest_rids)}")
print(f"   Unique record_ids from raw results field: {len(raw_rids)}")

# Check how many raw record_ids match the manifest formula
match_count = 0
for line in lines:
    r = json.loads(line)
    sid = r.get('sample_id', '')
    rid = r.get('record_id', '')
    if sid in sample_map:
        sm = sample_map[sid]
        expected_rid = sm['record_id_manifest']
        if rid == expected_rid:
            match_count += 1

print(f"   Raw record_ids matching manifest formula: {match_count} / {total_lines}")

# 3. Per unique relative paths and disk hashes
relative_paths = set()
disk_hashes = set()
for s in samples:
    relative_paths.add(s['file_path'])
    disk_hashes.add(s['disk_sha256'])

print(f"\n3. PATH AND HASH COUNTS (from manifest)")
print(f"   Distinct relative paths: {len(relative_paths)}")
print(f"   Distinct disk SHA-256 hashes: {len(disk_hashes)}")

# 4. Duplicate file_path groups
from collections import defaultdict
path_to_samples = defaultdict(list)
for s in samples:
    path_to_samples[s['file_path']].append(s['sample_id'])

dup_path_groups = {fp: sids for fp, sids in path_to_samples.items() if len(sids) > 1}
print(f"\n4. DUPLICATE file_path groups: {len(dup_path_groups)}")
print(f"   Expected: 16 (per IDENTITY_AUDIT.md)")
print(f"   Actual: {len(dup_path_groups)}")

# Show first 5
for i, (fp, sids) in enumerate(list(dup_path_groups.items())[:5]):
    print(f"   {fp}: {sids[:3]}...")

# 5. Check if raw_results has experiment_id field
experiment_id_present = False
for line in lines[:10]:
    r = json.loads(line)
    if 'experiment_id' in r and r['experiment_id'] is not None:
        experiment_id_present = True
        print(f"\n5. experiment_id field present in raw results: YES")
        print(f"   First value: {r['experiment_id']}")
        break
else:
    print(f"\n5. experiment_id field present in raw results: NO (all have experiment_id: None or field absent)")

# 6. Summary of all counts
print(f"\n6. ACCOUNTING SUMMARY")
print(f"   Physical lines: {total_lines}")
print(f"   Unique raw record_ids: {len(raw_rids)}")
print(f"   Unique manifest-derived rids: {len(manifest_rids)}")
print(f"   Matching: {match_count}")
print(f"   Distinct relative paths: {len(relative_paths)}")
print(f"   Distinct disk hashes: {len(disk_hashes)}")
print(f"   Duplicate file_path groups: {len(dup_path_groups)} (expected 16)")
print(f"   experiment_id field: {'present' if experiment_id_present else 'absent/None'}")