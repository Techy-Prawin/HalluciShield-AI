import sys, hashlib
from pathlib import Path
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
from evaluation.dataset_b.dataset_loader import DatasetBLoader
loader = DatasetBLoader()
all_samples = loader.get_samples()

# Compute experiment_id = sha256(file_path + ":" + disk_sha256) using actual disk SHA256
for s in all_samples:
    file_path = s['file_path']
    # Read actual disk file to get correct SHA256
    disk_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset\dataset-b') / file_path
    if disk_path.exists():
        with open(disk_path, 'rb') as f:
            disk_sha = hashlib.sha256(f.read()).hexdigest()
    else:
        disk_sha = s.get('sha256', '')  # fallback to metadata sha256
    
    exp_id = hashlib.sha256((file_path + ':' + disk_sha).encode()).hexdigest()
    s['experiment_id'] = exp_id

# Count unique
from collections import Counter
exp_id_counts = Counter(s['experiment_id'] for s in all_samples)
unique_exp_ids = set(s['experiment_id'] for s in all_samples)

print(f"Total samples: {len(all_samples)}")
print(f"Unique experiment_ids: {len(unique_exp_ids)}")
print(f"Using disk SHA256: {sum(1 for s in all_samples if hashlib.sha256(open((Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset\dataset-b') / s['file_path']), 'rb').read()).hexdigest() == s.get('sha256', ''))}")

# Show duplicates
dup_exp = {eid: cnt for eid, cnt in exp_id_counts.items() if cnt > 1}
if dup_exp:
    print(f"Duplicate experiment_id groups: {len(dup_exp)}")
    for eid, cnt in list(dup_exp.items())[:5]:
        samples_with_eid = [s for s in all_samples if s['experiment_id'] == eid]
        print(f"  {eid[:8]}: {cnt} samples")
        for s in samples_with_eid[:2]:
            print(f"    sample_id: {s['sample_id']}, file_path: {s['file_path'][:50]}")
else:
    print("No duplicate experiment_ids - all 500 are unique")