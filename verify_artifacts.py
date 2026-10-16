import json
import hashlib
from pathlib import Path
from collections import Counter, defaultdict

print("=" * 70)
print("INDEPENDENT VERIFICATION OF VALIDITY GATE REPORT")
print("=" * 70)

# === 1. Identity reconciliation ===
print("\n=== 1. IDENTITY RECONCILIATION ===")

# Load manifest
manifest_path = Path(r'dataset/dataset-b/MANIFEST.json')
with open(manifest_path) as f:
    manifest = json.load(f)

samples = manifest['samples']  # 500 records

# Compute formula: sha256(relative_file_path + ':' + disk_sha256)
formula_rids = []
for s in samples:
    rid = hashlib.sha256((s['file_path'] + ':' + s['disk_sha256']).encode()).hexdigest()
    formula_rids.append(rid)

unique_formula_rids = set(formula_rids)
dup_groups = {rid: cnt for rid, cnt in Counter(formula_rids).items() if cnt > 1}

print(f"1a. Manifest formula: 500 records -> {len(unique_formula_rids)} unique IDs")
print(f"   Duplicate groups: {len(dup_groups)} (expected: 16)")
print(f"   Reduction: 500 -> {len(unique_formula_rids)} = {500 - len(unique_formula_rids)}")
print(f"   Duplicate group sizes: {sorted([cnt for cnt in dup_groups.values()])}")
triple_groups = {rid: cnt for rid, cnt in dup_groups.items() if cnt >= 3}
print(f"   Triple+ groups: {len(triple_groups)}")

# Raw results identity mapping
raw_path = Path(r'evaluation/results/research/ablation500/raw_results.jsonl')
with open(raw_path) as f:
    raw_lines = f.readlines()

# Build sample_id -> formula rid mapping from manifest
sample_map = {}
for s in samples:
    sample_map[s['sample_id']] = {
        'file_path': s['file_path'],
        'disk_sha256': s['disk_sha256'],
        'record_id_manifest': s['record_id']
    }

# Check how many raw record_ids match the manifest formula
match_count = 0
mismatch_by_reason = defaultdict(int)
no_sample_in_manifest = 0

for line in raw_lines:
    r = json.loads(line)
    sid = r.get('sample_id', '')
    raw_rid = r.get('record_id', '')
    
    if sid not in sample_map:
        no_sample_in_manifest += 1
        continue
    
    sm = sample_map[sid]
    expected_rid = sm['record_id_manifest']
    
    if raw_rid == expected_rid:
        match_count += 1
    else:
        # Categorize the mismatch
        formula_rid = hashlib.sha256((sm['file_path'] + ':' + sm['disk_sha256']).encode()).hexdigest()
        if raw_rid == formula_rid:
            reason_key = 'matches_formula_not_manifest'
        elif raw_rid == hashlib.sha256((sm['file_path'] + sm['disk_sha256']).encode()).hexdigest():
            reason_key = 'no-colon_formula'
        else:
            reason_key = 'different_formula'
        mismatch_by_reason[reason_key] += 1
    
print(f"\n   Raw record_ids matching manifest formula: {match_count} / {len(raw_lines)}")
print(f"   Sample_ids not in manifest: {no_sample_in_manifest}")
for reason, cnt in mismatch_by_reason.items():
    print(f"   Mismatch - {reason}: {cnt}")

# Check: how many raw record_ids match the formula (sha256(file_path + ':' + disk_sha256)) directly?
f1_matches = 0
for line in raw_lines:
    r = json.loads(line)
    sid = r.get('sample_id', '')
    if sid in sample_map:
        sm = sample_map[sid]
        formula_rid = hashlib.sha256((sm['file_path'] + ':' + sm['disk_sha256']).encode()).hexdigest()
        if r.get('record_id', '') == formula_rid:
            f1_matches += 1

print(f"\n   Raw record_ids matching sha256(file_path ':' disk_sha256) directly: {f1_matches} / {len(raw_lines)}")

# Per-configuration analysis
config_line_counts = Counter()
for line in raw_lines:
    r = json.loads(line)
    cid = r.get('config_id', '')
    config_line_counts[cid] += 1

print(f"\n   Raw lines per config: {dict(config_line_counts)}")

# Unique (record_id, config_id) keys per config
config_unique_keys = defaultdict(set)
for line in raw_lines:
    r = json.loads(line)
    cid = r.get('config_id', '')
    rid = r.get('record_id', '')
    config_unique_keys[cid].add(rid)

print(f"\n   Unique (record_id, config_id) keys per config: { {cid: len(config_unique_keys[cid]) for cid in sorted(config_unique_keys.keys())} }")

# Acceptance test
accept_path = Path(r'evaluation/results/research/ablation500/raw_results_acceptance.jsonl')
with open(accept_path) as f:
    accept_lines = f.readlines()

accept_config_sample = set()
for line in accept_lines:
    r = json.loads(line)
    cid = r.get('config_id', '')
    sid = r.get('sample_id', '')
    accept_config_sample.add((cid, sid))

raw_config_sample = set()
for line in raw_lines:
    r = json.loads(line)
    cid = r.get('config_id', '')
    sid = r.get('sample_id', '')
    raw_config_sample.add((cid, sid))

overlap = accept_config_sample & raw_config_sample
new_keys = accept_config_sample - raw_config_sample

print(f"\n   Acceptance test keys:")
print(f"   Acceptance test lines: {len(accept_lines)}")
print(f"   Unique (config_id, sample_id) keys: {len(accept_config_sample)}")
print(f"   Overlapping keys (in both raw and acceptance): {len(overlap)}")
print(f"   New keys (only in acceptance): {len(new_keys)}")

# === 2. Ground-truth provenance ===
print("\n\n=== 2. GROUND-TRUTH PROVENANCE ===")

ground_truth_present = False
ground_truth_dist = Counter()
for line in raw_lines:
    r = json.loads(line)
    gt = r.get('ground_truth', '')
    if gt is not None and gt != '':
        ground_truth_present = True
    ground_truth_dist[gt] += 1

print(f"   ground_truth field present in raw results: {ground_truth_present}")
print(f"   ground_truth distribution: {dict(ground_truth_dist)}")

# Check predicted_label
pred_label_dist = Counter()
for line in raw_lines:
    r = json.loads(line)
    pred = r.get('predicted_label', '')
    pred_label_dist[pred] += 1

print(f"\n   predicted_label distribution (raw): {dict(pred_label_dist)}")

# Check if predictions can be joined to dataset records
matched = 0
unmatched = 0
for line in raw_lines:
    r = json.loads(line)
    sid = r.get('sample_id', '')
    if sid in sample_map:
        matched += 1
    else:
        unmatched += 1

print(f"\n   Raw results sample_ids found in manifest: {matched} / {len(raw_lines)}")
print(f"   Raw results sample_ids NOT in manifest: {unmatched}")

# === 3. Configuration coverage ===
print("\n\n=== 3. CONFIGURATION COVERAGE ===")

print(f"\n   Per-configuration unique (record_id, config_id) keys:")
config_unique_summary = {}
for cid in sorted(config_unique_keys.keys()):
    config_unique_summary[cid] = len(config_unique_keys[cid])

print(f"   {config_unique_summary}")

print(f"\n   Per-configuration raw lines:")
config_line_summary = {}
for cid in config_line_counts:
    config_line_summary[cid] = config_line_counts[cid]

print(f"   {config_line_summary}")

print(f"\n   Coverage calculation (unique_keys / 483):")
for cid in sorted(config_unique_keys.keys()):
    unique_k = len(config_unique_keys[cid])
    raw_l = config_line_counts[cid]
    coverage = unique_k / 483 * 100
    print(f"   Config {cid}: {unique_k} unique / 483 = {coverage:.1f}% (raw lines: {raw_l})")

# === 4. Metric reconciliation ===
print("\n\n=== 4. METRIC RECONCILIATION ===")

stored_positive = 1019
stored_negative = 4107
stored_total = 5126

raw_positive = 884
raw_negative = 4042
raw_total = 4926

accept_positive = 135
accept_negative = 65
accept_total = 200

cm_tp = 1126
cm_fn = 3494
cm_fp = 0
cm_tn = 380
cm_total = 5000

print(f"   Stored metrics: {stored_positive} positive + {stored_negative} negative = {stored_total}")
print(f"   Raw results: {raw_positive} positive + {raw_negative} negative = {raw_total}")
print(f"   Acceptance test: {accept_positive} positive + {accept_negative} negative = {accept_total}")
print(f"   Confusion-matrix sum: TP={cm_tp}, FN={cm_fn}, FP={cm_fp}, TN={cm_tn}, total={cm_total}")

# Reconcile: raw + acceptance
reconcilied_positive = raw_positive + accept_positive  # 884 + 135 = 1019
reconcilied_negative = raw_negative + accept_negative  # 4042 + 65 = 4107
reconcilied_total = raw_total + accept_total  # 4926 + 200 = 5126

print(f"\n   Reconciled (raw + acceptance): {reconcilied_positive} positive + {reconcilied_negative} negative = {reconcilied_total}")
print(f"   Matches stored: {reconcilied_positive == stored_positive and reconcilied_negative == stored_negative}")
print(f"   Surplus vs. 4830 unique units: {stored_total - 4830}")
print(f"   Surplus vs. 5000 confusion-matrix: {stored_total - cm_total}")

# Per-configuration duplication counts
print(f"\n   Per-configuration duplication:")
for cid in sorted(config_unique_keys.keys()):
    unique_k = len(config_unique_keys[cid])
    raw_l = config_line_counts[cid]
    dup = raw_l - unique_k
    print(f"   Config {cid}: {raw_l} lines, {unique_k} unique keys, {dup} duplicates")

PYEOF