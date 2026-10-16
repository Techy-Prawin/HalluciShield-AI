import json
from pathlib import Path

print("=" * 70)
print("DEEP METRICS.JSON INSPECTION")
print("=" * 70)

metrics_path = Path(r'evaluation/results/research/ablation500/metrics.json')
with open(metrics_path) as f:
    metrics = json.load(f)

print(f"\nMetrics.json loaded. Top-level keys: {list(metrics.keys())}")

# Dump structure, first 5000 chars
full_dump = json.dumps(metrics, indent=2)
print(f"\nFirst 5000 chars of metrics.json:")
print(full_dump[:5000])

# Also check if there are nested confusion matrices
print("\n\n--- Looking for confusion matrices or per-config metrics ---")
def find_keys(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                print(f"  {full}: {type(v).__name__} (len={len(v) if hasattr(v,'__len__') else 'N/A'})")
            else:
                print(f"  {full}: {str(v)[:80]}")
            find_keys(v, full)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            full = f"prefix][{i}]" if prefix else f"[{i}]"
            if isinstance(item, (dict, list)):
                print(f"  {full}: {type(item).__name__}")
            else:
                print(f"  {full}: {str(item)[:80]}")

find_keys(metrics)