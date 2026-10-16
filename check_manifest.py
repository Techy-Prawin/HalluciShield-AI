import json, hashlib, os
from pathlib import Path

# Read manifest
manifest_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\dataset_b\MANIFEST.json')
with open(manifest_path) as f:
    manifest = json.load(f)

print(f"Manifest has {len(manifest)} entries")

# Compute record_id = sha256(relative_file_path + ":" + disk_sha256) for each entry
record_ids = []
for i, entry in enumerate(manifest):
    rel_path = entry.get('file_path', '')
    disk_sha = entry.get('disk_sha256', '')
    record_id = hashlib.sha256((rel_path + ':' + disk_sha).encode()).hexdigest()
    record_ids.append(record_id)

from collections import Counter
rcount = Counter(record_ids)
unique_rids = set(record_ids)
print(f"Total record_ids: {len(record_ids)}")
print(f"Unique record_ids: {len(unique_rids)}")
print(f"Duplicate record_id groups: {len(record_ids) - len(unique_rids)}")

# Show duplicate groups
dups = {rid: cnt for rid, cnt in rcount.items() if cnt > 1}
if dups:
    print(f"Duplicate record_id groups (first 10): {list(dups.items())[:10]}")
    
# Show first few entries
for i in range(5):
    print(f"Entry {i}: file_path={manifest[i].get('file_path','')[:50]}, disk_sha256={manifest[i].get('disk_sha256','')[:16]}, record_id={record_ids[i][:16]}")