import hashlib
import sys
from pathlib import Path

sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
from evaluation.dataset_b.dataset_loader import DatasetBLoader

loader = DatasetBLoader()
all_samples = loader.get_samples()

# Find DS-B-0416
target_samples = [s for s in all_samples if s['sample_id'] == 'DS-B-0416']
if target_samples:
    s = target_samples[0]
    file_path = s['file_path']
    disk_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset\dataset-b') / file_path
    with open(disk_path, 'rb') as f:
        disk_sha = hashlib.sha256(f.read()).hexdigest()
    exp_id = hashlib.sha256((file_path + ':' + disk_sha).encode()).hexdigest()
    print(f'DS-B-0416: file_path={file_path}')
    print(f'  disk_sha256={disk_sha[:16]}...')
    print(f'  experiment_id={exp_id[:16]}...')

    # Find all samples with this experiment_id
    print('\nAll samples with same experiment_id:')
    for s2 in all_samples:
        fp = s2['file_path']
        dp = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset\dataset-b') / fp
        if dp.exists():
            with open(dp, 'rb') as f:
                ds = hashlib.sha256(f.read()).hexdigest()
        else:
            ds = s2.get('sha256', '')
        eid = hashlib.sha256((fp + ':' + ds).encode()).hexdigest()
        if eid == exp_id:
            sid = s2['sample_id']
            print(f'  {sid}, file_path={fp[:50]}')
else:
    print('DS-B-0416 not found')