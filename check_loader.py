import json
from evaluation.dataset_b.dataset_loader import DatasetBLoader

loader = DatasetBLoader()
samples = loader.get_samples()
sample = samples[0]
print("First sample keys:", list(sample.keys()))
print("sample_id:", sample.get("sample_id"))
print("record_id:", sample.get("record_id", "NOT PRESENT"))
print("label:", sample.get("label"))
print("file_path:", sample.get("file_path"))
print("category:", sample.get("category"))
print("cwe:", sample.get("cwe"))
print("language:", sample.get("language"))
print()
# Check if record_id matches manifest
with open(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset-b\MANIFEST.json') as f:
    manifest = json.load(f)
manifest_sample = [s for s in manifest['samples'] if s['sample_id'] == sample['sample_id']][0]
print("Manifest record_id:", manifest_sample.get("record_id"))
print("Manifest file_path:", manifest_sample.get("file_path"))