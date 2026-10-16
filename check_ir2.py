import json
from pathlib import Path

manifest_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset-b\MANIFEST.json')
with open(manifest_path) as f:
    manifest = json.load(f)
print("MANIFEST.json type:", type(manifest).__name__)
print("MANIFEST.json num keys:", len(manifest))
if len(manifest) > 0:
    first_key = list(manifest.keys())[0]
    print("First key:", first_key)
    rec = manifest[first_key]
    print("First record keys:", list(rec.keys()))
    for k in ['record_id', 'experiment_id', 'disk_sha256', 'relative_file_path', 'sample_id', 'metadata_sha256']:
        if k in rec:
            v = rec[k]
            print("  " + k + ":", str(v)[:80] if v else 'None')

# Check integrity_report.json
ir_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\results\research\ablation500\integrity_report.json')
with open(ir_path) as f:
    ir = json.load(f)
print("\nintegrity_report.json keys:", list(ir.keys()))
for key in ['unique_experiment_ids', 'total_records', '483_experiment_ids', 'discrepancy', 'experiment_id_formula', 'experimental_population']:
    if key in ir:
        print("  " + key + ":", ir[key])