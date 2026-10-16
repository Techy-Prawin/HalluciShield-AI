import json
from pathlib import Path
from collections import Counter

raw_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\ablation500\raw_results.jsonl')
with open(raw_path) as f:
    lines = f.readlines()

# Collect all identity fields
record_ids = set()
experiment_ids = set()
sample_ids = set()
configs = set()
all_keys = set()

# Also track which config each record_id appears with
record_configs = {}

for line in lines:
    r = json.loads(line)
    rid = r.get('record_id', '')
    eid = r.get('experiment_id', '')
    sid = r.get('sample_id', '')
    cid = r.get('config_id', '')
    
    record_ids.add(rid)
    experiment_ids.add(eid)
    sample_ids.add(sid)
    configs.add(cid)
    
    key = (rid, cid)
    all_keys.add(key)
    
    if rid not in record_configs:
        record_configs[rid] = set()
    record_configs[rid].add(cid)

print("Unique record_ids:", len(record_ids))
print("Unique experiment_ids:", len(experiment_ids))
print("Unique sample_ids:", len(sample_ids))
print("Unique config_ids:", len(configs))
print("Unique (record_id, config_id) keys:", len(all_keys))

# Show duplicate record_ids
rid_counts = Counter()
for line in lines:
    r = json.loads(line)
    rid = r.get('record_id', '')
    rid_counts[rid] += 1

dup_rids = {k: v for k, v in rid_counts.items() if v > 1}
print("\nDuplicate record_ids:", len(dup_rids))
for rid, cnt in list(dup_rids.items())[:3]:
    print("  ", rid, ":", cnt, "occurrences")
    configs_with_rid = record_configs.get(rid, set())
    print("    Appears with configs:", configs_with_rid)

# Show the actual record_id values and their counts
print("\nrecord_id distribution (top 10):")
rid_count_list = sorted(rid_counts.items(), key=lambda x: x[1], reverse=True)
for rid, cnt in rid_count_list[:10]:
    print("  ", rid, ":", cnt)

# Show all unique record_ids and their counts
print("\nAll record_ids and counts:")
for rid, cnt in rid_counts.items():
    print("  ", rid, ":", cnt)
PYEOF