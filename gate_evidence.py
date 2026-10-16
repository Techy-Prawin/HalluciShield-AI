import json
import hashlib
from pathlib import Path
from collections import Counter, defaultdict

print("=" * 70)
print("PHASE 5.6 INDEPENDENT VALIDITY GATE AUDIT")
print("=" * 70)

# === 2. File locations ===
print("\n=== 2. FILE LOCATIONS ===")
files_to_check = [
    r'dataset/dataset-b/MANIFEST.json',
    r'dataset/dataset-b/IDENTITY_AUDIT.md',
    r'evaluation/results/research/ablation500/raw_results.jsonl',
    r'evaluation/results/research/ablation500/raw_results_acceptance.jsonl',
    r'evaluation/results/research/ablation500/metrics.json',
    r'evaluation/results/research/ablation500/config.json',
    r'evaluation/results/research/ablation500/integrity_report.json',
    r'evaluation/results/research/ablation500/trace_summary.json',
    r'evaluation/results/research/ablation500/provenance_summary.json',
    r'evaluation/results/research/ablation500/checkpoint.json',
]
for f in files_to_check:
    p = Path(f)
    exists = p.exists()
    print(f"  {'EXISTS' if exists else 'MISSING'}: {f}")