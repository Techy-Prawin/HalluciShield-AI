import json
from pathlib import Path

manifest_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset-b\MANIFEST.json')
with open(manifest_path) as f:
    manifest = json.load(f)
print("MANIFEST.json type:", type(manifest).__name__)
print("MANIFEST.json num keys:", len(manifest))
# Check first value
first_key = list(manifest.keys())[0]
print("First key:", first_key)
print("First value type:", type(manifest[first_key]).__name__)
if isinstance(manifest[first_key], dict):
    rec = manifest[first_key]
    print("First record keys:", list(rec.keys()))
    for k in ['record_id', 'experiment_id', 'disk_sha256', 'relative_file_path', 'sample_id', 'metadata_sha256']:
        if k in rec:
            v = rec[k]
            print("  " + k + ":", str(v)[:80] if v else 'None')
elif isinstance(manifest[first_key], list):
    print("First value is a list with", len(manifest[first_key]), "items")