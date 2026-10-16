import json
from pathlib import Path

print("=" * 70)
print("METRICS AND CONFIG INSPECTION")
print("=" * 70)

# 1. metrics.json
metrics_path = Path(r'evaluation/results/research/ablation500/metrics.json')
with open(metrics_path) as f:
    metrics = json.load(f)

print("\n1. METRICS.JSON - Top-level keys:")
print(f"   Keys: {list(metrics.keys())}")

# Check for per-configuration data
for key in ['per_config_summary', 'confusion_matrices', 'aece_comparison', 'category_metrics', 'language_metrics', 'multi_patch_comparison']:
    if key in metrics:
        print(f"\n   {key}:")
        val = metrics[key]
        if isinstance(val, dict):
            print(f"     Type: dict, keys: {list(val.keys())[:10]}")
            # Show first key's value structure
            first_key = list(val.keys())[0] if val else None
            if first_key:
                print(f"     First key '{first_key}': {type(val[first_key]).__name__}")
                if isinstance(val[first_key], dict):
                    print(f"       Sub-keys: {list(val[first_key].keys())}")
        elif isinstance(val, list):
            print(f"     Type: list, length: {len(val)}")
            if val and isinstance(val[0], dict):
                print(f"       First item keys: {list(val[0].keys())}")

# 2. config.json
config_path = Path(r'evaluation/results/research/ablation500/config.json')
with open(config_path) as f:
    config = json.load(f)

print("\n\n2. CONFIG.JSON:")
print(f"   Gate verdict: {config.get('gate_verdict', 'N/A')}")
print(f"   Keys: {list(config.keys())}")

# Check for experiment config
for key in ['experiment_population', 'num_units', 'expected_units', 'configurations']:
    if key in config:
        print(f"   {key}: {config[key]}")

# 3. Acceptance test artifacts
print("\n\n3. ACCEPTANCE TEST ARTIFACTS")

# Check for acceptance test results
import glob
at_files = glob.glob(r'evaluation/results/research/ablation500/*acceptance*')
at_files += glob.glob(r'evaluation/results/research/ablation500/*Acceptance*')
at_files += glob.glob(r'evaluation/results/research/ablation500/*Acceptance_Test*')
print(f"   Files matching acceptance pattern: {at_files}")

# Check raw_results_acceptance.jsonl
accept_path = Path(r'evaluation/results/research/ablation500/raw_results_acceptance.jsonl')
if accept_path.exists():
    with open(accept_path) as f:
        at_lines = f.readlines()
    print(f"   raw_results_acceptance.jsonl: {len(at_lines)} lines")
    at_valid = 0
    at_malformed = 0
    for line in at_lines:
        try:
            json.loads(line)
            at_valid += 1
        except json.JSONDecodeError:
            at_malformed += 1
    print(f"   Valid JSON: {at_valid}, Malformed: {at_malformed}")
    
    # Count unique keys and predictions
    at_record_ids = set()
    at_config_keys = set()
    at_pred_pos = 0
    at_pred_neg = 0
    for line in at_lines:
        r = json.loads(line)
        rid = r.get('record_id', '')
        cid = r.get('config_id', '')
        at_record_ids.add(rid)
        at_config_keys.add((rid, cid))
        pred = r.get('predicted_label', '')
        if pred == 'positive':
            at_pred_pos += 1
        elif pred == 'negative':
            at_pred_neg += 1
    print(f"   Unique record_ids: {len(at_record_ids)}")
    print(f"   Unique (record_id, config_id) keys: {len(at_config_keys)}")
    print(f"   Predictions: positive={at_pred_pos}, negative={at_pred_neg}")
else:
    print("   raw_results_acceptance.jsonl: NOT FOUND")

# 4. Integrity report
ir_path = Path(r'evaluation/results/research/ablation500/integrity_report.json')
if ir_path.exists():
    with open(ir_path) as f:
        ir = json.load(f)
    print(f"\n   integrity_report.json keys: {list(ir.keys())}")
    for key in ['unique_experiment_ids', 'total_records', 'experimental_population', 'raw_results', 'acceptance_test', 'combined_results', '483_experiment_ids', 'discrepancy']:
        if key in ir:
            print(f"   {key}: {ir[key]}")