import json
from pathlib import Path

# Check integrity_report.json
ir_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\ablation500\integrity_report.json')
with open(ir_path) as f:
    ir = json.load(f)
print("integrity_report.json keys:", list(ir.keys()))

# Check key fields
for key in ['unique_experiment_ids', 'total_records', '483_experiment_ids', 'discrepancy', 'experiment_id_formula']:
    if key in ir:
        print("\n" + key + ":", ir[key])

# Check manifest
manifest_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset-b\MANIFEST.json')
with open(manifest_path) as f:
    manifest = json.load(f)
print("\nMANIFEST.json type:", type(manifest).__name__)
print("MANIFEST.json length:", len(manifest) if isinstance(manifest, list) else "N/A")
if isinstance(manifest, list) and len(manifest) > 0:
    rec = manifest[0]
    print("First record keys:", list(rec.keys()))
    for k in ['record_id', 'experiment_id', 'disk_sha256', 'relative_file_path', 'sample_id', 'metadata_sha256']:
        if k in rec:
            v = rec[k]
            print("  " + k + ":", str(v)[:50] if v else 'None')