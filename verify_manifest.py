#!/usr/bin/env python3
"""Verify manifest content and hash matching."""

import json

m = json.load(open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset-b\MANIFEST.json'))

# Check first sample details
s = m['samples'][0]
print('Sample 0:')
print(f'  sample_id: {s["sample_id"]}')
print(f'  file_path: {s["file_path"]}')
print(f'  disk_sha256: {s["disk_sha256"]}')
print(f'  metadata_sha256: {s["metadata_sha256"]}')
print(f'  match: {s["disk_sha256"] == s["metadata_sha256"]}')
print(f'  record_id: {s["record_id"][:20]}...')
print()

# Check how many have same disk_sha256 vs metadata_sha256
matches = sum(1 for s in m['samples'] if s['disk_sha256'] == s['metadata_sha256'])
print(f'Total disk==metadata matches: {matches}/500')

# Show a group with same sample_id
# DS-B-0039 appears twice
ds0039 = [s for s in m['samples'] if s['sample_id'] == 'DS-B-0039']
print(f'\nDS-B-0039 entries:')
for e in ds0039:
    print(f'  file_path: {e["file_path"]}')
    print(f'  disk_sha256: {e["disk_sha256"]}')
    print(f'  record_id: {e["record_id"][:20]}...')
    print(f'  label: {e["label"]}, cwe: {e["cwe"]}, category: {e["category"]}')

# Show duplicate sample_id group
print('\n--- Duplicate sample_id analysis ---')
# Check DS-B-0039 entries have different content
e0, e1 = ds0039
print(f'DS-B-0039 file_paths: {e0["file_path"]} vs {e1["file_path"]}')
print(f'DS-B-0039 disk_sha256: {e0["disk_sha256"]} vs {e1["disk_sha256"]}')
print(f'DS-B-0039 record_ids: {e0["record_id"][:20]}... vs {e1["record_id"][:20]}...')
print(f'DS-B-0039 records differ: {e0["record_id"] != e1["record_id"]}')