import json, collections
from pathlib import Path

raw_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\ablation500\raw_results.jsonl')
with open(raw_path) as f:
    lines = f.readlines()

print(f'Total lines: {len(lines)}')

# Check first few entries structure
for i in range(0, 3):
    r = json.loads(lines[i])
    print(f'Entry {i} keys: {list(r.keys())}')
    print(f'  record_id: {r.get("record_id")[:16]}...')
    print(f'  config_id: {r.get("config_id")}')
    print(f'  prediction: {r.get("prediction")}')
    print(f'  execution_status: {r.get("execution_status")}')
    print()

# Count by config_id
config_counts = collections.Counter()
for line in lines:
    r = json.loads(line)
    cid = r.get('config_id')
    if cid:
        config_counts[cid] += 1
print(f'Config distribution: {dict(config_counts)}')

# Count unique (record_id, config_id) keys
keys = set()
for line in lines:
    r = json.loads(line)
    rid = r.get('record_id', '')
    cid = r.get('config_id', '')
    keys.add((rid, cid))
print(f'Unique (record_id, config_id) keys: {len(keys)}')