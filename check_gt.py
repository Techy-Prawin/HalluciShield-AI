import json
from pathlib import Path
from collections import Counter

raw_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\ablation500\raw_results.jsonl')
with open(raw_path) as f:
    lines = f.readlines()

# Analyze ground_truth and predicted_label relationship
pos_from_gt_pos = 0
pos_from_gt_neg = 0
neg_from_gt_pos = 0
neg_from_gt_neg = 0

gt_pos_count = 0
gt_neg_count = 0

for line in lines:
    r = json.loads(line)
    gt = r.get('ground_truth', '')
    pred = r.get('predicted_label', '')
    decision = r.get('decision', '')
    
    if gt == 'positive':
        gt_pos_count += 1
        if pred == 'positive':
            pos_from_gt_pos += 1
        else:
            pos_from_gt_neg += 1
    elif gt == 'negative':
        gt_neg_count += 1
        if pred == 'positive':
            neg_from_gt_pos += 1
        else:
            neg_from_gt_neg += 1

print("ground_truth vs predicted_label:")
print("  ground_truth=positive, predicted=positive:", pos_from_gt_pos)
print("  ground_truth=positive, predicted=negative:", pos_from_gt_neg)
print("  ground_truth=negative, predicted=positive:", neg_from_gt_pos)
print("  ground_truth=negative, predicted=negative:", neg_from_gt_neg)
print("  Total ground_truth=positive:", gt_pos_count)
print("  Total ground_truth=negative:", gt_neg_count)

# Analyze config_id distribution with record_id
rid_config_counts = Counter()
for line in lines:
    r = json.loads(line)
    rid = r.get('record_id', '')
    cid = r.get('config_id', '')
    rid_config_counts[(rid, cid)] += 1

# Count how many (record_id, config_id) keys have duplicates
dup_keys = sum(1 for k, v in rid_config_counts.items() if v > 1)
total_keys = len(rid_config_counts)
print("\nUnique (record_id, config_id) keys:", total_keys)
print("Duplicate (record_id, config_id) keys:", dup_keys)
print("Non-duplicate keys:", total_keys - dup_keys)

# Per-configuration line counts
config_counts = Counter()
for line in lines:
    r = json.loads(line)
    cid = r.get('config_id', '')
    config_counts[cid] += 1

print("\nLines per config_id:")
for cid in sorted(config_counts.keys()):
    print("  ", cid, ":", config_counts[cid])

# Per-configuration prediction counts
config_pred_pos = Counter()
config_pred_neg = Counter()
for line in lines:
    r = json.loads(line)
    cid = r.get('config_id', '')
    pred = r.get('predicted_label', '')
    if pred == 'positive':
        config_pred_pos[cid] += 1
    elif pred == 'negative':
        config_pred_neg[cid] += 1

print("\nPredictions per config_id:")
for cid in sorted(config_pred_pos.keys()):
    print("  ", cid, "positive:", config_pred_pos[cid], "negative:", config_pred_neg[cid])
PYEOF