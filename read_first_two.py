import json
with open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\dataset_b\full_ace\raw_results.jsonl') as f:
    for i, line in enumerate(f):
        if i >= 2: break
        r = json.loads(line)
        sid = r.get("sample_id", "unknown")
        pl = r.get("predicted_label", "unknown")
        ss = r.get("scanner_status", "unknown")
        vs = r.get("validation_status", "unknown")
        ac = r.get("ace_score", "unknown")
        print(f"Sample {i}: sample_id={sid}, predicted_label={pl}, scanner_status={ss}, validation_status={vs}, ace_score={ac}")