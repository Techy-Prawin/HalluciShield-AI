import sys, hashlib
from pathlib import Path
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
from evaluation.dataset_b.dataset_loader import DatasetBLoader
loader = DatasetBLoader()
all_samples = loader.get_samples()

# Check what 'sha256' field contains
print('First 3 samples sha256 field:')
for s in all_samples[:3]:
    sid = s['sample_id']
    sha_meta = s.get('sha256', '')
    print(f'  sample_id: {sid}')
    print(f'    metadata_sha256: {sha_meta[:32]}...')
    print(f'  file_path: {s["file_path"][:50]}')

# Check disk SHA256 by reading actual files
print('\nComputing disk SHA256 for first 3 samples:')
for s in all_samples[:3]:
    sid = s['sample_id']
    file_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset\dataset-b') / s['file_path']
    if file_path.exists():
        with open(file_path, 'rb') as f:
            disk_sha = hashlib.sha256(f.read()).hexdigest()
        print(f'  {sid}: metadata_sha256={sha_meta[:16]}..., disk_sha256={disk_sha[:16]}...')
        print(f'    Match: {sha_meta == disk_sha}')
    else:
        print(f'  {sid}: FILE NOT FOUND')