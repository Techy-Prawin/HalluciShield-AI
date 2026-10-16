import json
from pathlib import Path

manifest_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset-b\MANIFEST.json')
with open(manifest_path) as f:
    manifest = json.load(f)
print("MANIFEST.json type:", type(manifest).__name__)
print("MANIFEST.json num keys:", len(manifest))
# Print all keys and value types
for k, v in manifest.items():
    print("  key:", k, "value_type:", type(v).__name__, "value_len:", len(v) if hasattr(v, '__len__') else 'N/A')
    if hasattr(v, '__len__') and len(v) > 0 and isinstance(v[0], dict):
        rec = v[0]
        print("    first record keys:", list(rec.keys()))
        for field in ['record_id', 'experiment_id', 'disk_sha256', 'relative_file_path', 'sample_id', 'metadata_sha256']:
            if field in rec:
                print("    " + field + ":", str(rec[field])[:50] if rec[field] else 'None')