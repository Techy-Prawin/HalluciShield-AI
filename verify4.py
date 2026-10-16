import json
from pathlib import Path
import os

print("=" * 70)
print("CHECKPOINTS, TRACES, AND PROVENANCE")
print("=" * 70)

# 1. Checkpoint file
cp_path = Path(r'evaluation/results/research/ablation500/checkpoint.json')
if cp_path.exists():
    with open(cp_path) as f:
        cp = json.load(f)
    print("\n1. CHECKPOINT.JSON:")
    print(f"   {json.dumps(cp, indent=2)[:2000]}")
else:
    print("\n1. CHECKPOINT.JSON: NOT FOUND")

# 2. Trace summary
ts_path = Path(r'evaluation/results/research/ablation500/trace_summary.json')
if ts_path.exists():
    with open(ts_path) as f:
        ts = json.load(f)
    print("\n2. TRACE_SUMMARY.JSON:")
    print(f"   {json.dumps(ts, indent=2)[:2000]}")
else:
    print("\n2. TRACE_SUMMARY.JSON: NOT FOUND")

# 3. Provenance summary
ps_path = Path(r'evaluation/results/research/ablation500/provenance_summary.json')
if ps_path.exists():
    with open(ps_path) as f:
        ps = json.load(f)
    print("\n3. PROVENANCE_SUMMARY.JSON:")
    print(f"   {json.dumps(ps, indent=2)[:2000]}")
else:
    print("\n3. PROVENANCE_SUMMARY.JSON: NOT FOUND")

# 4. Per-configuration metrics that we need to sum
# Let me compute the total from the per-configusion confusion matrices in metrics.json
print("\n\n4. SUMMING PER-CONFIGUSION MATRICES FROM METRICS.JSON")

metrics_path = Path(r'evaluation/results/research/ablation500/metrics.json')
with open(metrics_path) as f:
    metrics = json.load(f)

# Sum tp, fn across all configs
total_tp = 0
total_fn = 0
total_fp = 0
total_tn = 0
for cid in sorted(metrics['configurations'].keys()):
    cm = metrics['configurations'][cid]['detection']['confusion_matrix']
    total_tp += cm['tp']
    total_fn += cm['fn']
    total_fp += cm['fp']
    total_tn += cm['tn']
    cid_name = metrics['configurations'][cid]['config_name']

print(f"   Summing confusion matrices across 10 configurations:")
print(f"   Total TP: {total_tp}")
print(f"   Total FN: {total_fn}")
print(f"   Total FP: {total_fp}")
print(f"   Total TN: {total_tn}")
print(f"   Total actual positives (TP+FN): {total_tp + total_fn}")
print(f"   Total actual negatives (FP+TN): {total_fp + total_tn}")
print(f"   Grand total: {total_tp + total_fn + total_fp + total_tn}")

# Compare with stored totals
print(f"\n   Stored positive predictions: 1019")
print(f"   Stored negative predictions: 4107")
print(f"   Stored total: 5126")
print(f"   Matrix sum total: {total_tp + total_fn + total_fp + total_tn}")
print(f"   Difference: {5126 - (total_tp + total_fn + total_fp + total_tn)}")

# Per-config prediction totals (from raw results, not metrics.json)
print("\n\n5. PER-CONFIGURATION LINE COUNTS vs. CONFUSION MATRIX SUMS")

# From verify1.py we have:
raw_config_counts = {'A': 495, 'B': 495, 'C': 495, 'D': 483, 'E': 495, 'F': 483, 'G': 495, 'H': 495, 'I': 495, 'J': 495}

# From the confusion matrix sums:
print(f"   Config lines (raw): {sum(raw_config_counts.values())}")
print(f"   Matrix sum total: {total_tp + total_fn + total_fp + total_tn}")
print(f"   Difference: {sum(raw_config_counts.values()) - (total_tp + total_fn + total_fp + total_tn)}")

# Check provenance counts
print("\n\n6. PROVENANCE COUNTS IN METRICS.JSON")
for cid in ['A', 'D', 'F', 'G', 'J']:
    pc = metrics['configurations'][cid]['evidence_confidence']['provenance_counts']
    print(f"   Config {cid} provenance: {pc}")
    # REAL + NOT_AVAILABLE + SYNTHETIC_TEST should relate to total
    total_pc = sum(pc.values())
    print(f"      Sum: {total_pc} (expected: 500 or 483 or 484)")