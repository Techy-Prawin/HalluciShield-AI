import json
from pathlib import Path

raw_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\ablation500\raw_results.jsonl')
with open(raw_path) as f:
    lines = f.readlines()

# Check what fields exist in raw_results
field_names = set()
for line in lines:
    r = json.loads(line)
    field_names.update(r.keys())
print("All field names in raw_results.jsonl:")
for fn in sorted(field_names):
    print("  ", fn)

# Check how many distinct config_name values
config_names = set()
for line in lines:
    r = json.loads(line)
    config_names.add(r.get('config_name', ''))
print("\nUnique config_name values:")
for cn in sorted(config_names):
    print("  ", cn)