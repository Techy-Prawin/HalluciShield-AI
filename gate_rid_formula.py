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

# For mismatched records, determine what formula produces their record_id
# Known formulas:
# F1: sha256(file_path + ':' + disk_sha256)  -- this is the "manifest formula"
# F2: sha256(file_path + disk_sha256) no colon
# F3: sha256(disk_sha256 + ':' + file_path)
# F4: maybe the record_id is just based on sample_id or something else

mismatch_analysis = defaultdict(Counter)

for line in raw_lines:
    r = json.loads(line)
    raw_rid = r.get('record_id', '')
    sid = r.get('sample_id', '')
    cid = r.get('config_id', '')
    
    if sid not in sample_map:
        continue  # sample_id not in manifest, skip
    
    sm = sample_map[sid]
    
    # Compute all formulas
    f1 = hashlib.sha256((sm['file_path'] + ':' + sm['disk_sha256']).encode()).hexdigest()  # manifest formula
    f2 = hashlib.sha256((sm['file_path'] + sm['disk_sha256']).encode()).hexdigest()  # no colon
    f3 = hashlib.sha256((sm['disk_sha256'] + ':' + sm['file_path']).encode()).hexdigest()  # reversed colon
    f4 = hashlib.sha256(sm['file_path'].encode()).hexdigest()  # just file_path
    f5 = hashlib.sha256(sm['disk_sha256'].encode()).hexdigest()  # just disk_sha256
    # f6 not needed - sample_id is the dict key, not a field in the sample record
    
    # Which formula matches the raw record_id?
    if raw_rid == f1:
        formula = "F1: file_path ':' disk_sha256"
    elif raw_rid == f2:
        formula = "F2: file_path disk_sha256 no-colon"
    elif raw_rid == f3:
        formula = "F3: disk_sha256 ':' file_path reversed"
    elif raw_rid == f4:
        formula = "F4: file_path only"
    elif raw_rid == f5:
        formula = "F5: disk_sha256 only"
    elif raw_rid == f6:
        formula = "F6: sample_id only"
    else:
        formula = "NO MATCH"
    
    mismatch_analysis[formula][raw_rid[:16]] += 1

# Also count how many match F1 (the manifest formula)
f1_matches = 0
for line in raw_lines:
    r = json.loads(line)
    sid = r.get('sample_id', '')
    if sid in sample_map:
        sm = sample_map[sid]
        f1 = hashlib.sha256((sm['file_path'] + ':' + sm['disk_sha256']).encode()).hexdigest()
        if r.get('record_id', '') == f1:
            f1_matches += 1

print(f"\nF1 (manifest formula) matches: {f1_matches} / {len(raw_lines)}")

# Show the mismatch analysis
print(f"\nMismatch analysis - what formula produces the raw record_ids that DON'T match F1:")
for formula, rid_counts in mismatch_analysis.items():
    total = sum(rid_counts.values())
    print(f"  {formula}: {total} records with this formula producing the raw record_id")
    # Show a few examples
    for rid, cnt in rid_counts.most_common(3):
        print(f"    {rid[:16]}: {cnt} records")

# Now check: of the records where F1 doesn't match, how many have sample_ids that are in the 
# 108 duplicate sample_id groups (all different content)?
print("\n\nKey question: Are the 1358 mismatched records from duplicate sample_id groups?")

# Count how many of the mismatched records have sample_ids from duplicate groups
# From IDENTITY_AUDIT.md: 108 duplicate sample_id groups, all with DIFFERENT content
# Let me check the sample_id distribution in raw results
sample_id_counts = Counter()
for line in raw_lines:
    r = json.loads(line)
    sample_id_counts[r.get('sample_id', '')] += 1

dup_sample_ids = {sid for sid, cnt in sample_id_counts.items() if cnt > 1}
print(f"Sample_ids appearing more than once in raw results: {len(dup_sample_ids)}")

# Of the 1358 mismatches, how many have dup sample_ids?
# We need to count: among the 4926 records, how many have sample_ids that appear multiple times?
# And of those, how many mismatches?

# Actually, let me just check: of the mismatched records (where F1 doesn't match), what's the sample_id situation?
mismatch_sample_ids = set()
for line in raw_lines:
    r = json.loads(line)
    raw_rid = r.get('record_id', '')
    sid = r.get('sample_id', '')
    if sid in sample_map:
        sm = sample_map[sid]
        f1 = hashlib.sha256((sm['file_path'] + ':' + sm['disk_sha256']).encode()).hexdigest()
        if raw_rid != f1:
            mismatch_sample_ids.add(sid)

print(f"\nSample_ids with mismatched record_ids (F1 doesn't match): {len(mismatch_sample_ids)}")

# Of these, how many are in the duplicate sample_id groups?
# From IDENTITY_AUDIT.md, there are 108 duplicate sample_id groups
# Let me check the overlap
print(f"Sample_ids in known duplicate groups (108 groups): need to check against IDENTITY_AUDIT.md data")

# Let me just print a sample of the mismatched sample_ids
print(f"\nSample of mismatched sample_ids:")
mis_list = list(mismatch_sample_ids)[:10]
for sid in mis_list:
    # Get the sample info from manifest
    for s in samples:
        if s['sample_id'] == sid:
            print(f"  {sid}: file_path={s['file_path'][:30]}, disk_sha256={s['disk_sha256'][:16]}")
            break