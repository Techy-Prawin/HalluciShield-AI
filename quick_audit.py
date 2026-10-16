import sys, json, hashlib
from pathlib import Path
from collections import Counter

_REPO_ROOT = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / 'ai-engine'))

from evaluation.dataset_b.evaluator import load_all_samples_info

all_samples = load_all_samples_info()

# Group by record_id
record_groups = {}
for s in all_samples:
    rid = s.get('record_id', 'MISSING')
    if rid not in record_groups:
        record_groups[rid] = []
    record_groups[rid].append(s)

# Find duplicated record_ids
duplicated = {rid: recs for rid, recs in record_groups.items() if len(recs) > 1}
print(f'Duplicated record_ids: {len(duplicated)}')

# Show details for each duplicated group
for rid in sorted(duplicated.keys()):
    recs = duplicated[rid]
    sample_ids = [r.get('sample_id', 'MISSING') for r in recs]
    file_paths = [r.get('file_path', 'MISSING') for r in recs]
    cwe_vals = [r.get('cwe', 'MISSING') for r in recs]
    lang_vals = [r.get('language', 'MISSING') for r in recs]
    cat_vals = [r.get('category', 'MISSING') for r in recs]
    
    print(f'\nrecord_id = {rid} (count: {len(recs)})')
    print(f'  sample_ids: {sample_ids}')
    print(f'  file_paths: {file_paths}')
    print(f'  cwe_vals: {cwe_vals}')
    print(f'  lang_vals: {lang_vals}')
    print(f'  cat_vals: {cat_vals}')