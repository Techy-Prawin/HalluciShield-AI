import json
from pathlib import Path
from collections import Counter

raw_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\ablation500\raw_results.jsonl')
with open(raw_path) as f:
    lines = f.readlines()

print(f'Total lines: {len(lines)}')

# Check status distribution
statuses = Counter()
predictions = Counter()
for line in lines:
    r = json.loads(line)
    if 'predicted_label' in r:
        predictions[r['predicted_label']] += 1
    if 'execution_status' in r:
        statuses[r['execution_status']] += 1

print(f'Predicted labels: {dict(predictions)}')
print(f'Execution statuses: {dict(statuses)}')

# Show first result
r = json.loads(lines[0])
print(f'First result keys: {list(r.keys())}')
pl = r.get('predicted_label')
es = r.get('execution_status')
print(f'First result predicted_label: {pl}')
print(f'First result execution_status: {es}')
print(f'First result config: {r.get("config")}')