import sys, os
from pathlib import Path
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
from evaluation.dataset_b.dataset_loader import DatasetBLoader
loader = DatasetBLoader()
all_samples = loader.get_samples()
sample_ids = [s['sample_id'] for s in all_samples]
from collections import Counter
id_counts = Counter(sample_ids)
print(f"Total: {len(all_samples)}, Unique: {len(id_counts)}")
print(f"Duplicates: {sum(1 for k,v in id_counts.items() if v > 1)}")
dup_ids = {k:v for k,v in id_counts.items() if v > 1}
if dup_ids:
    print(f"Duplicate groups: {list(dup_ids.items())[:5]}")
print(f"Sample IDs: {list(id_counts.keys())[:10]}...")