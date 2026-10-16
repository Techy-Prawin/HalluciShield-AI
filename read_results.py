import json
with open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\dataset_b\semgrep\raw_results.jsonl', 'r') as f:
    for i, line in enumerate(f):
        if i >= 5: 
            break
        r = json.loads(line)
        print(f'predicted: {r["predicted_label"]}, detection_correct: {r["detection_correct"]}, fp: {r["false_positive"]}, fn: {r["false_negative"]}')