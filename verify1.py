import json
from pathlib import Path
from collections import Counter

print("=" * 70)
print("PHASE 5.6 PUBLICATION EVIDENCE VERIFICATION")
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

# 2. Unique identifier enumeration
record_ids = set()
experiment_ids = set()
sample_ids = set()
configs = set()
unit_config_keys = set()

record_configs = {}

for line in lines:
    r = json.loads(line)
    rid = r.get('record_id', '')
    eid = r.get('experiment_id', '')
    sid = r.get('sample_id', '')
    cid = r.get('config_id', '')
    
    record_ids.add(rid)
    if eid:
        experiment_ids.add(eid)
    sample_ids.add(sid)
    configs.add(cid)
    
    key = (rid, cid)
    unit_config_keys.add(key)
    
    if rid not in record_configs:
        record_configs[rid] = set()
    record_configs[rid].add(cid)

print(f"\n2. UNIQUE IDENTIFIERS")
print(f"   Unique record_ids: {len(record_ids)}")
print(f"   Unique experiment_ids: {len(experiment_ids)}")
print(f"   Unique sample_ids: {len(sample_ids)}")
print(f"   Unique config_ids: {len(configs)}")
print(f"   Unique (record_id, config_id) keys: {len(unit_config_keys)}")

# 3. Duplicate analysis
rid_counts = Counter()
for line in lines:
    r = json.loads(line)
    rid = r.get('record_id', '')
    rid_counts[rid] += 1

dup_rids = {k: v for k, v in rid_counts.items() if v > 1}
print(f"\n3. DUPLICATE record_ids")
print(f"   Duplicate record_ids: {len(dup_rids)}")
top_dups = sorted(dup_rids.items(), key=lambda x: x[1], reverse=True)[:5]
for rid, cnt in top_dups:
    configs_with_rid = record_configs.get(rid, set())
    print(f"   {rid[:16]}: {cnt} occurrences, configs: {configs_with_rid}")

# Per-configuration line counts and unique record_ids
unique_rid_per_config = {}
dup_key_per_config = {}
for line in lines:
    r = json.loads(line)
    cid = r.get('config_id', '')
    rid = r.get('record_id', '')
    if cid not in unique_rid_per_config:
        unique_rid_per_config[cid] = set()
    unique_rid_per_config[cid].add(rid)
    if cid not in dup_key_per_config:
        dup_key_per_config[cid] = Counter()
    dup_key_per_config[cid][rid] += 1

print(f"\n4. PER-CONFIGURATION LINE COUNTS AND UNIQUE record_ids")
for cid in sorted(config_counts.keys() if 'config_counts' in dir() else []):
    pass

# Actually compute config_counts first
config_counts = Counter()
for line in lines:
    r = json.loads(line)
    cid = r.get('config_id', '')
    config_counts[cid] += 1

print(f"\n4. PER-CONFIGURATION LINE COUNTS AND UNIQUE record_ids")
for cid in sorted(config_counts.keys()):
    total = config_counts[cid]
    unique = len(unique_rid_per_config.get(cid, set()))
    print(f"   Config {cid}: {total} lines, {unique} unique record_ids, {total - unique} redundant entries")

# 5. Prediction counts per config
config_pred_pos = Counter()
config_pred_neg = Counter()
for line in lines:
    r = json.loads(line)
    cid = r.get('config_id', '')
    pred = r.get('predicted_label', '')
    if pred == 'positive':
        config_pred_pos[cid] += 1
    elif pred == 'negative':
        config_pred_neg[cid] += 1

print(f"\n5. PREDICTION COUNTS PER CONFIGURATION")
for cid in sorted(config_pred_pos.keys()):
    pos = config_pred_pos[cid]
    neg = config_pred_neg[cid]
    total = config_counts[cid]
    print(f"   Config {cid}: positive={pos}, negative={neg}, total={total}")

# 6. Summary of 296 surplus
stored_tp = 1019
stored_fn = 4107
raw_pos = 884
raw_neg = 4042
print(f"\n6. 296-OUTCOME SURPLUS ANALYSIS")
print(f"   Raw predictions: {raw_pos} positive + {raw_neg} negative = {raw_pos + raw_neg}")
print(f"   Stored metrics:  {stored_tp} positive + {stored_fn} negative = {stored_tp + stored_fn}")
print(f"   Surplus: {stored_tp + stored_fn - (raw_pos + raw_neg)} = {stored_tp + stored_fn - raw_pos - raw_neg}")
print(f"   Surplus breakdown: {stored_tp + stored_fn} - {raw_pos + raw_neg} = {stored_tp - raw_pos} positive surplus + {stored_fn - raw_neg} negative surplus")
print(f"   Positive surplus: {stored_tp - raw_pos} = {stored_tp - raw_pos}")
print(f"   Negative surplus: {stored_fn - raw_neg} = {stored_fn - raw_neg}")