import json
with open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\evaluation\results\research\ablation500\raw_results.jsonl') as f:
    lines = f.readlines()
print(f'Total lines: {len(lines)}')
for i, line in enumerate(lines[:5]):
    r = json.loads(line)
    print(f'Line {i}: sample_id={r.get("sample_id")}, record_id={r.get("record_id")}, config_id={r.get("config_id")}')