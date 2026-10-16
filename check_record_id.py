import json
import hashlib
from pathlib import Path
import os

# Read raw_results.jsonl and check record_id computation
raw_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\ablation500\raw_results.jsonl')
with open(raw_path) as f:
    lines = f.readlines()

# Read manifest to get disk_sha256 and file_path
manifest_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset-b\MANIFEST.json')
with open(manifest_path) as f:
    manifest = json.load(f)

samples = manifest['samples']  # 500 records

# Build a map from sample_id to record info
sample_map = {}
for s in samples:
    sid = s['sample_id']
    file_path = s['file_path']  # as stored in metadata, e.g., "positive/cwe89/cwe89_001.py"
    disk_sha256 = s['disk_sha256']
    record_id_manifest = s['record_id']  # sha256(relative_file_path + ':' + disk_sha256)
    actual_path = s.get('actual_path', '')
    exists = s.get('exists', False)
    sample_map[sid] = {
        'file_path': file_path,
        'disk_sha256': disk_sha256,
        'record_id_manifest': record_id_manifest,
        'actual_path': actual_path,
        'exists': exists
    }

# Now check raw_results record_ids
rid_counts = {}
for i, line in enumerate(lines):
    r = json.loads(line)
    rid = r.get('record_id', '')
    sid = r.get('sample_id', '')
    cid = r.get('config_id', '')
    config_name = r.get('config_name', '')
    
    if sid not in sample_map:
        print(f"Record {i}: sample_id {sid} NOT in manifest!")
        continue
    
    sm = sample_map[sid]
    expected_rid = sm['record_id_manifest']
    
    # Also compute what record_id WOULD be using the formula
    # record_id = sha256(relative_file_path + ':' + disk_sha256)
    # The relative_file_path from manifest is sm['file_path']
    computed_rid = hashlib.sha256(
        (sm['file_path'] + ':' + sm['disk_sha256']).encode()
    ).hexdigest()
    
    match_manifest = (rid == expected_rid)
    match_computed = (rid == computed_rid)
    
    key = (rid, cid)
    rid_counts[key] = rid_counts.get(key, 0) + 1
    
    if i < 20:  # First 20 records
        print(f"Record {i}: sample_id={sid}, rid={rid[:16]}, expected_rid={expected_rid[:16]}, computed={computed_rid[:16]}, match_manifest={match_manifest}, match_computed={match_computed}, config={cid}, config_name={config_name}, exists={sm['exists']}")

# Summary
print("\n--- Summary ---")
print("Total records checked:", len(lines))

# Count how many record_ids match the manifest formula
match_manifest_total = 0
match_computed_total = 0
for i, line in enumerate(lines):
    r = json.loads(line)
    sid = r.get('sample_id', '')
    rid = r.get('record_id', '')
    if sid in sample_map:
        expected_rid = sample_map[sid]['record_id_manifest']
        computed_rid = hashlib.sha256(
            (sample_map[sid]['file_path'] + ':' + sample_map[sid]['disk_sha256']).encode()
        ).hexdigest()
        if rid == expected_rid:
            match_manifest_total += 1
        if rid == computed_rid:
            match_computed_total += 1

print("record_ids matching manifest formula:", match_manifest_total, "/", len(lines))
print("record_ids matching computed formula:", match_computed_total, "/", len(lines))

# Check duplicate (record_id, config_id) keys
from collections import Counter
key_counts = Counter()
for line in lines:
    r = json.loads(line)
    rid = r.get('record_id', '')
    cid = r.get('config_id', '')
    key_counts[(rid, cid)] += 1

dup_keys = {k: v for k, v in key_counts.items() if v > 1}
print("Duplicate (record_id, config_id) keys:", len(dup_keys))
print("Total unique (record_id, config_id) keys:", len(key_counts))

# Per-configuration analysis using manifest-derived record_ids
print("\n--- Per-configuration analysis using manifest record_ids ---")
config_record_ids = {}
for line in lines:
    r = json.loads(line)
    rid = r.get('record_id', '')
    cid = r.get('config_id', '')
    sid = r.get('sample_id', '')
    if sid in sample_map:
        if cid not in config_record_ids:
            config_record_ids[cid] = set()
        config_record_ids[cid].add(rid)

for cid in sorted(config_record_ids.keys()):
    unique_rids = len(config_record_ids[cid])
    # Total lines for this config from earlier
    config_lines = sum(1 for line in lines if json.loads(line).get('config_id') == cid)
    print(f"Config {cid}: {config_lines} lines, {unique_rids} unique record_ids")

# Also compute what 483 unique experiment_ids would look like
# experiment_id = sha256(file_path + ':' + disk_sha256) per IDENTITY_AUDIT.md recommended formula
print("\n--- Experiment ID analysis (sha256(file_path + ':' + disk_sha256)) ---")
exp_ids = set()
for line in lines:
    r = json.loads(line)
    sid = r.get('sample_id', '')
    cid = r.get('config_id', '')
    if sid in sample_map:
        sm = sample_map[sid]
        exp_id = hashlib.sha256(
            (sm['file_path'] + ':' + sm['disk_sha256']).encode()
        ).hexdigest()
        exp_ids.add(exp_id)

print("Unique experiment_ids (sha256(file_path + ':' + disk_sha256)):", len(exp_ids))

# Per-configuration experiment_ids
for cid in sorted(config_record_ids.keys()):
    exp_cid = set()
    for line in lines:
        r = json.loads(line)
        if r.get('config_id') == cid:
            sid = r.get('sample_id', '')
            if sid in sample_map:
                sm = sample_map[sid]
                exp_id = hashlib.sha256(
                    (sm['file_path'] + ':' + sm['disk_sha256']).encode()
                ).hexdigest()
                exp_cid.add(exp_id)
    print(f"Config {cid} unique experiment_ids: {len(exp_cid)}")
PYEOF