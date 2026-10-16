import json
from pathlib import Path

raw_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\ablation500\raw_results.jsonl')
with open(raw_path) as f:
    lines = f.readlines()

# Check experiment_id field in first few records
for i in range(min(5, len(lines))):
    r = json.loads(lines[i])
    rid = r.get('record_id', '')
    eid = r.get('experiment_id', '')
    cid = r.get('config_id', '')
    pred = r.get('predicted_label', '')
    print('Record', i, ':')
    print('  record_id:', rid[:20] if rid else 'None')
    print('  experiment_id:', eid[:20] if eid else 'None')
    print('  config_id:', cid)
    print('  predicted_label:', pred)
    print('  keys:', list(r.keys())[:8])
    print()