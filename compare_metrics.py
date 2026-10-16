import json, collections
from pathlib import Path

# Read raw results
raw_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\ablation500\raw_results.jsonl')
with open(raw_path) as f:
    raw_lines = f.readlines()

# Compute per-configuration metrics from raw results
raw_configMetrics = {}
for line in raw_lines:
    r = json.loads(line)
    cid = r.get('config_id', '')
    rid = r.get('record_id', '')
    
    if cid not in raw_configMetrics:
        raw_configMetrics[cid] = {'total': 0, 'pred_positive': 0}
    
    raw_configMetrics[cid]['total'] += 1
    if r.get('predicted_label') == 'positive':
        raw_configMetrics[cid]['pred_positive'] += 1

# Compare with integrity_report.json metrics
metrics_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\ablation500\metrics.json')
with open(metrics_path) as f:
    stored_metrics = json.load(f)

print("PER-CONFIGURATION METRICS COMPARISON")
print("=" * 70)
for cfg in ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J']:
    if cfg in raw_configMetrics:
        rm = raw_configMetrics[cfg]
        sm = stored_metrics['configurations'][cfg]['detection']
        tp = sm['confusion_matrix']['tp']
        fn = sm['confusion_matrix']['fn']
        fp = sm['confusion_matrix']['fp']
        tn = sm['confusion_matrix']['tn']
        stored_precision = sm['precision']
        stored_recall = sm['recall']
        stored_f1 = sm['f1']
        stored_accuracy = sm['accuracy']
        
        print(f"\nConfig {cfg}:")
        print(f"  Raw: total={rm['total']}, pos_pred={rm['pred_positive']}")
        print(f"  Stored: tp={tp}, fn={fn}, fp={fp}, tn={tn}")
        print(f"  Stored: precision={stored_precision}, recall={stored_recall}, f1={stored_f1}, accuracy={stored_accuracy}")

print("\n" + "=" * 70)
rt = sum(rm['total'] for rm in raw_configMetrics.values())
rp = sum(rm['pred_positive'] for rm in raw_configMetrics.values())
print(f"\nRaw totals: total={rt}, pos_pred={rp}")
print(f"Stored total positive: 1019 (from integrity_report)")
print(f"Stored total negative: 4107 (from integrity_report)")