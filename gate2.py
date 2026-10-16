import json
import hashlib
from pathlib import Path
from collections import Counter, defaultdict

print("=" * 70)
print("DEEP DIVE: 350 vs 483 IDENTITY DISCREPANCY")
print("=" * 70)

# Load manifest
manifest_path = Path(r'dataset/dataset-b/MANIFEST.json')
with open(manifest_path) as f:
    manifest = json.load(f)

samples = manifest['samples']  # 500 records

# For each sample, compute sha256(relative_file_path + ':' + disk_sha256)
formula_rids = []
rid_to_samples = defaultdict(list)
for s in samples:
    rid = hashlib.sha256((s['file_path'] + ':' + s['disk_sha256']).encode()).hexdigest()
    formula_rids.append(rid)
    rid_to_samples[rid].append(s['sample_id'])

unique_formula_rids = set(formula_rids)
print(f"\n1. Formula-derived IDs from 500 manifest samples:")
print(f"   Unique IDs: {len(unique_formula_rids)}")
print(f"   Total records: {len(formula_rids)}")

# Count duplicates
rid_counts = Counter(formula_rids)
dup_rids = {rid: cnt for rid, cnt in rid_counts.items() if cnt > 1}
print(f"\n   Duplicate ID groups: {len(dup_rids)}")
for rid, cnt in list(dup_rids.items())[:5]:
    samples_with_rid = rid_to_samples[rid]
    print(f"   {rid[:16]}: {cnt} records -> {samples_with_rid[:3]}...")

# Per-configuration analysis using raw results
print(f"\n2. Per-configuration analysis using raw results:")

# Rebuild sample_map from manifest
sample_map = {}
for s in samples:
    sample_map[s['sample_id']] = {
        'file_path': s['file_path'],
        'disk_sha256': s['disk_sha256'],
        'record_id_manifest': s['record_id']
    }

# Count formula-derived unique rids per config
for cid in sorted(sample_to_configs.keys()):
    config_sample_ids = sample_to_configs[cid]
    formula_rids_for_config = set()
    for sid in config_sample_ids:
        if sid in sample_map:
            sm = sample_map[sid]
            rid = hashlib.sha256((sm['file_path'] + ':' + sm['disk_sha256']).encode()).hexdigest()
            formula_rids_for_config.add(rid)
    print(f"   Config {cid}: {len(config_sample_ids)} sample_ids, {len(formula_rids_for_config)} formula-derived unique rids")

# Now check: how many (file_path, disk_sha256) pairs are unique?
path_hash_pairs = set()
for s in samples:
    path_hash_pairs.add((s['file_path'], s['disk_sha256']))
print(f"\n3. Unique (file_path, disk_sha256) pairs: {len(path_hash_pairs)} / 500")

# Check: how many records share a (file_path, disk_sha256) pair?
pair_counts = Counter()
for s in samples:
    pair_counts[(s['file_path'], s['disk_sha256'])] += 1
dup_pairs = {k: v for k, v in pair_counts.items() if v > 1}
print(f"   Duplicate (path, hash) pairs: {len(dup_pairs)}")
for pair, cnt in list(dup_pairs.items())[:5]:
    print(f"   {pair[0][:30]}... : {cnt} records")

# Check: how many records have unique (file_path, disk_sha256) pairs?
unique_pair_rids = 0
for pair, cnt in pair_counts.items():
    if cnt == 1:
        unique_pair_rids += 1
print(f"   Records with unique (path, hash) pair: {unique_pair_rids}")

# The key question: 350 formula rids vs 483 claimed
# Let me check: of the 500 records, how many have a (path, hash) pair that is unique?
# And how many formula rids are unique?
print(f"\n4. Summary:")
print(f"   500 metadata records")
print(f"   Unique formula-derived IDs: {len(unique_formula_rids)} = 350")
print(f"   Unique (file_path, disk_sha256) pairs: {len(path_hash_pairs)} = {len(path_hash_pairs)}")
print(f"   Duplicate (path, hash) pairs: {len(dup_pairs)}")
print(f"   Records with unique pairs: {unique_pair_rids}")
print(f"   Previous audit claim: 483 unique experiment_ids")
print(f"   Discrepancy: 483 - 350 = 133 unaccounted records")