"""Final verification of Phase 4.1 output files."""
import json
from pathlib import Path

results_dir = Path("evaluation/results/owasp")

required = [
    "raw_results.jsonl", "metrics.json", "confusion_matrix.json",
    "cwe_metrics.json", "owasp_top10_mapping.json", "experiment_config.json", "README.md"
]
print("=== Required output files ===")
for fname in required:
    p = results_dir / fname
    size = p.stat().st_size if p.exists() else -1
    status = "OK" if size > 0 else "MISSING/EMPTY"
    print(f"  {fname}: {size} bytes — {status}")

count = sum(1 for line in open(results_dir / "raw_results.jsonl", encoding="utf-8") if line.strip())
print(f"\nraw_results.jsonl lines: {count}")

with open(results_dir / "metrics.json") as f:
    m = json.load(f)
print(f"\nstatus: {m['status']}")
print(f"total_test_cases: {m['total_test_cases']}")
print(f"oracle_positive: {m['oracle_positive']}  oracle_negative: {m['oracle_negative']}")
print(f"confusion_matrix: {m['confusion_matrix']}")
print(f"metrics: {m['metrics']}")
print(f"execution_counts: {m['execution_counts']}")
print(f"integrity.oracle_labels_verified: {m['integrity']['oracle_labels_verified']}")
print(f"integrity.no_duplicates: {m['integrity']['no_duplicates']}")
print(f"integrity.no_gt_leakage: {m['integrity']['no_gt_leakage']}")
print(f"integrity.no_error_to_clean: {m['integrity']['no_error_to_clean']}")
print(f"integrity.fabricated_values: {m['integrity']['fabricated_values']}")

with open(results_dir / "cwe_metrics.json") as f:
    cwe = json.load(f)
print(f"\nCWE groups ({len(cwe)}): {list(cwe.keys())}")

db_results = Path("evaluation/results/dataset_b")
if db_results.exists():
    db_files = list(db_results.iterdir())
    print(f"\nDataset B results (untouched): {[f.name for f in db_files[:5]]}")
else:
    print("\nDataset B results: directory not in results/")

print("\nVerification complete.")
