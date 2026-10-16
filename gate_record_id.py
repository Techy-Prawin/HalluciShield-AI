import json
import hashlib
from pathlib import Path
from collections import Counter, defaultdict

print("=" * 70)
print("INVESTIGATING RECORD_ID FORMULA DISCREPANCY")
print("=" * 70)

manifest_path = Path(r'dataset/dataset-b/MANIFEST.json')
with open(manifest_path) as f:
    manifest = json.load(f)

samples = manifest['samples']  # 500 records
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

# For each raw record, try to determine what formula produces its record_id
# Try various formulas and see which matches

mismatches_detail = []
match_count = 0
mismatch_count = 0

for i, line in enumerate(raw_lines[:50]):  # First 50 for analysis
    r = json.loads(line)
    raw_rid = r.get('record_id', '')
    sid = r.get('sample_id', '')
    cid = r.get('config_id', '')
    
    if sid not in sample_map:
        mismatches_detail.append(f"Row {i}: sample_id {sid} not in manifest")
        mismatch_count += 1
        continue
    
    sm = sample_map[sid]
    
    # Try formula 1: sha256(file_path + ':' + disk_sha256)
    rid1 = hashlib.sha256((sm['file_path'] + ':' + sm['disk_sha256']).encode()).hexdigest()
    
    # Try formula 2: sha256(file_path + disk_sha256) no colon
    rid2 = hashlib.sha256((sm['file_path'] + sm['disk_sha256']).encode()).hexdigest()
    
    # Try formula 3: sha256(disk_sha256 + ':' + file_path)
    rid3 = hashlib.sha256((sm['disk_sha256'] + ':' + sm['file_path']).encode()).hexdigest()
    
    # Try formula 4: just the raw record_id from manifest (no formula)
    rid4 = sm['record_id_manifest']
    
    # Try formula 5: sha256(record_id from metadata) 
    # Maybe the raw record_id is just the sample_id or something else
    
    if raw_rid == rid1:
        formula_match = "sha256(file_path ':' disk_sha256) ✓"
    elif raw_rid == rid2:
        formula_match = "sha256(file_path disk_sha256) no-colon"
    elif raw_rid == rid3:
        formula_match = "sha256(disk_sha256 ':' file_path)"
    elif raw_rid == rid4:
        formula_match = "manifest record_id (no formula)"
    else:
        formula_match = "NO MATCH"
        mismatch_count += 1
        mismatches_detail.append(f"Row {i}: {formula_match}, config={cid}, sample={sid}")
    
    if raw_rid in [rid1, rid2, rid3, rid4]:
        match_count += 1

print(f"First 50 records: {match_count} match a formula, {mismatch_count} don't")

# Show mismatches
print(f"\nMismatch details (first 5):")
for m in mismatches_detail[:5]:
    print(f"  {m}")

# Now check ALL 4926 records for formula1 match
print("\n\nAll 4926 records - formula1 (sha256(file_path ':' disk_sha256)) matches:")
match_all = 0
for line in raw_lines:
    r = json.loads(line)
    sid = r.get('sample_id', '')
    raw_rid = r.get('record_id', '')
    if sid in sample_map:
        sm = sample_map[sid]
        rid1 = hashlib.sha256((sm['file_path'] + ':' + sm['disk_sha256']).encode()).hexdigest()
        if raw_rid == rid1:
            match_all += 1

print(f"  sha256(file_path ':' disk_sha256) matches: {match_all} / {len(raw_lines)}")

# Check formula2 (no colon)
match_all2 = 0
for line in raw_lines:
    r = json.loads(line)
    sid = r.get('sample_id', '')
    raw_rid = r.get('record_id', '')
    if sid in sample_map:
        sm = sample_map[sid]
        rid2 = hashlib.sha256((sm['file_path'] + sm['disk_sha256']).encode()).hexdigest()
        if raw_rid == rid2:
            match_all2 += 1
print(f"  sha256(file_path disk_sha256) no-colon matches: {match_all2} / {len(raw_lines)}")

# Check: what does the raw record_id look like? Just sample_id hash?
# Let me check the first few raw record_ids and their sample_ids
print("\nFirst 10 raw record_ids and sample_ids:")
for i in range(10):
    r = json.loads(raw_lines[i])
    print(f"  sample_id={r.get('sample_id', '')[:16]}, record_id={r.get('record_id', '')[:16]}")

# Check: maybe the raw record_id is sha256 of just the file_path?
match_all3 = 0
for line in raw_lines:
    r = json.loads(line)
    sid = r.get('sample_id', '')
    raw_rid = r.get('record_id', '')
    if sid in sample_map:
        sm = sample_map[sid]
        rid3 = hashlib.sha256(sm['file_path'].encode()).hexdigest()
        if raw_rid == rid3:
            match_all3 += 1
print(f"  sha256(file_path) only matches: {match_all3} / {len(raw_lines)}")

# Maybe sha256 of just disk_sha256?
match_all4 = 0
for line in raw_lines:
    r = json.loads(line)
    sid = r.get('sample_id', '')
    raw_rid = r.get('record_id', '')
    if sid in sample_map:
        sm = sample_map[sid]
        rid4 = hashlib.sha256(sm['disk_sha256'].encode()).hexdigest()
        if raw_rid == rid4:
            match_all4 += 1
print(f"  sha256(disk_sha256) only matches: {match_all4} / {len(raw_lines)}")