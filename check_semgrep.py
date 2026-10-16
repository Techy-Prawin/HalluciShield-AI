import json
count = 0
with open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\dataset_b\semgrep\raw_results.jsonl', 'r') as f:
    for line in f:
        r = json.loads(line)
        if r['detection_correct'] or r['false_positive'] or r['false_negative']:
            print(f"sample_id: {r['sample_id']}, predicted: {r['predicted_label']}, detection_correct: {r['detection_correct']}, fp: {r['false_positive']}, fn: {r['false_negative']}")
        count += 1
print(f"Total samples: {count}")