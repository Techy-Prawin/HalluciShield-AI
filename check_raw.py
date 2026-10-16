import json
with open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\evaluation\results\research\ablation500\raw_results.jsonl') as f:
    for i, line in enumerate(f):
        if i >= 3: break
        r = json.loads(line)
        print(f'Sample {i}:')
        print(f'  sample_id: {r.get("sample_id")}')
        print(f'  record_id: {r.get("record_id")}')
        print(f'  config_id: {r.get("config_id")}')
        print(f'  predicted_label: {r.get("predicted_label")}')
        print(f'  all_findings_count: {r.get("all_findings_count")}')
        print(f'  stages_completed: {r.get("stages_completed")}')
        print(f'  label: {r.get("label")}')
        print()