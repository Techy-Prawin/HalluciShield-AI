import sys
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
from evaluation.dataset_b.dataset_loader import DatasetBLoader

loader = DatasetBLoader(
    metadata_csv=r"C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset-b\metadata.csv",
    files_root=r"C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset\dataset-b"
)

samples = loader.get_samples()
print(f"Total samples: {len(samples)}")
print(f"Positive: {sum(1 for s in samples if s.get('label') == 'positive')}")
print(f"Negative: {sum(1 for s in samples if s.get('label') == 'negative')}")