import json, collections
from pathlib import Path

# Acceptance test
acc_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\ablation500\raw_results_acceptance.jsonl')
with open(acc_path) as f:
    acc_lines = f.readlines()

acc_keys = set()
acc_preds = collections.Counter()
for line in acc_lines:
    r = json.loads(line)
    acc_keys.add((r.get('record_id', ''), r.get('config_id', '')))
    if 'predicted_label' in r:
        acc_preds[r['predicted_label']] += 1

print(f'Acceptance test unique keys: {len(acc_keys)}')
print(f'Acceptance predictions: {dict(acc_preds)}')

# First few acceptance keys
for line in acc_lines[:3]:
    r = json.loads(line)
    rid = r.get('record_id', '')[:16]
    cid = r.get('config_id')
    pred = r.get('predicted_label')
    print(f'  key: ({rid}..., {cid}) pred={pred}')

# Combined keys
raw_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\ablation500\raw_results.jsonl')
with open(raw_path) as f:
    raw_lines = f.readlines()

raw_keys = set()
for line in raw_lines:
    r = json.loads(line)
    raw_keys.add((r.get('record_id', ''), r.get('config_id', '')))

combined = raw_keys | acc_keys
print(f'\nCombined unique keys: {len(combined)}')
print(f'Task spec: 489 x 10 = 4890')
print(f'Coverage: {len(combined)/4890*100:.1f}%')