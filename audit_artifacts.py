import json, collections
from pathlib import Path

# Audit raw_results.jsonl
print("=" * 60)
print("AUDIT: raw_results.jsonl")
print("=" * 60)

raw_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\ablation500\raw_results.jsonl')
with open(raw_path) as f:
    raw_lines = f.readlines()

print(f"Total lines: {len(raw_lines)}")

raw_keys = set()
raw_preds = collections.Counter()
raw_statuses = collections.Counter()
raw_configs = collections.Counter()
raw_errors = 0
raw_timeouts = 0
raw_not_applicables = 0

for line in raw_lines:
    r = json.loads(line)
    raw_keys.add((r.get('record_id', ''), r.get('config_id', '')))
    raw_configs[r.get('config_id', '')] += 1
    
    if 'predicted_label' in r:
        raw_preds[r['predicted_label']] += 1
    
    es = r.get('execution_status')
    if es:
        raw_statuses[es] += 1
    else:
        raw_statuses['NONE'] += 1
    
    if r.get('error') and str(r['error']).strip():
        raw_errors += 1
    if r.get('elapsed', 0) > 120:
        raw_timeouts += 1
    if r.get('provenance') == 'NOT_APPLICABLE':
        raw_not_applicables += 1

print(f"Unique (record_id, config_id) keys: {len(raw_keys)}")
print(f"Predictions: {dict(raw_preds)}")
print(f"Execution statuses: {dict(raw_statuses)}")
print(f"Config distribution: {dict(raw_configs)}")
print(f"Lines with error field: {raw_errors}")
print(f"Lines with elapsed > 120s (potential timeout): {raw_timeouts}")
print(f"Lines with NOT_APPLICABLE provenance: {raw_not_applicables}")

# Per-config breakdown
print(f"\nPer-config line counts:")
for cfg in sorted(raw_configs.keys()):
    print(f"  {cfg}: {raw_configs[cfg]} lines")

# Audit acceptance test
print("\n" + "=" * 60)
print("AUDIT: raw_results_acceptance.jsonl")
print("=" * 60)

acc_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\ablation500\raw_results_acceptance.jsonl')
with open(acc_path) as f:
    acc_lines = f.readlines()

print(f"Total lines: {len(acc_lines)}")

acc_keys = set()
acc_preds = collections.Counter()
acc_statuses = collections.Counter()

for line in acc_lines:
    r = json.loads(line)
    acc_keys.add((r.get('record_id', ''), r.get('config_id', '')))
    if 'predicted_label' in r:
        acc_preds[r['predicted_label']] += 1
    es = r.get('execution_status')
    if es:
        acc_statuses[es] += 1
    else:
        acc_statuses['NONE'] += 1

print(f"Unique (record_id, config_id) keys: {len(acc_keys)}")
print(f"Predictions: {dict(acc_preds)}")
print(f"Execution statuses: {dict(acc_statuses)}")

# Combined audit
print("\n" + "=" * 60)
print("AUDIT: COMBINED (raw + acceptance)")
print("=" * 60)

all_lines = raw_lines + acc_lines
combined_keys = set()
combined_preds = collections.Counter()

for line in all_lines:
    r = json.loads(line)
    combined_keys.add((r.get('record_id', ''), r.get('config_id', '')))
    if 'predicted_label' in r:
        combined_preds[r['predicted_label']] += 1

print(f"Unique (record_id, config_id) keys (combined): {len(combined_keys)}")
print(f"Combined predictions: {dict(combined_preds)}")
print(f"Task spec: 489 x 10 = 4,890")
print(f"Coverage: {len(combined_keys)/4890*100:.1f}%")

# Check metrics.json
print("\n" + "=" * 60)
print("CHECK: metrics.json")
print("=" * 60)

metrics_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\ablation500\metrics.json')
with open(metrics_path) as f:
    metrics = json.load(f)
print(json.dumps(metrics, indent=2)[:2000])
PYEOF