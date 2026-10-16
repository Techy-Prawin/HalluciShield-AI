import json
from collections import Counter

with open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\evaluation\results\research\ablation500\raw_results.jsonl') as f:
    lines = f.readlines()

# Count predicted_labels and labels
pred_labels = []
true_labels = []
for line in lines:
    r = json.loads(line)
    pred_labels.append(r.get('predicted_label'))
    true_labels.append(r.get('label'))

pred_counts = Counter(pred_labels)
true_counts = Counter(true_labels)

print('Predicted label counts:', dict(pred_counts))
print('True label counts:', dict(true_counts))
print()

# Check first 5 entries
for i, line in enumerate(lines[:5]):
    r = json.loads(line)
    print(f'Entry {i}: sample_id={r.get("sample_id")}, config_id={r.get("config_id")}, predicted_label={r.get("predicted_label")}, label={r.get("label")}, all_findings_count={r.get("all_findings_count")}, stages_completed={r.get("stages_completed")}')