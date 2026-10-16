import sys
import os
import importlib.util
from collections import Counter

sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')

# Load DatasetB loader
spec = importlib.util.spec_from_file_location(
    "dataset_b.loader",
    r"C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\evaluation\dataset_b\dataset_loader.py"
)
loader_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loader_mod)
DatasetBLoader = loader_mod.DatasetBLoader

# Load samples
loader = DatasetBLoader(
    metadata_csv=r"C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset-b\metadata.csv",
    files_root=r"C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset\dataset-b"
)

samples = loader.get_samples()
print(f"Total samples: {len(samples)}")

# Show label distribution
labels = [s.get("label", "unknown") for s in samples]
label_counts = Counter(labels)
print(f"Label distribution: {dict(label_counts)}")

# Show category distribution
categories = [s.get("category", "unknown") for s in samples]
cat_counts = Counter(categories)
print(f"Category distribution: {dict(cat_counts)}")

# Show language distribution
languages = [s.get("language", "unknown") for s in samples]
lang_counts = Counter(languages)
print(f"Language distribution: {dict(lang_counts)}")

# Show CWE distribution
cwes = [s.get("cwe", "unknown") for s in samples]
cwe_counts = Counter(cwes)
print(f"CWE distribution: {dict(cwe_counts)}")

# Show first 15 sample IDs (to help select balanced 20)
print("\nFirst 15 sample_ids with details:")
for i, s in enumerate(samples[:15]):
    sid = s.get("sample_id", "unknown")
    lbl = s.get("label", "unknown")
    cat = s.get("category", "unknown")
    lang = s.get("language", "unknown")
    cwe = s.get("cwe", "unknown")
    print(f"  {i+1}. {sid}: label={lbl}, category={cat}, language={lang}, cwe={cwe}")

# Also check file existence
print(f"\nFile existence check:")
fp_count = 0
missing_count = 0
for s in samples[:20]:
    fp = loader.get_file_path(s)
    exists = fp.exists() if hasattr(fp, 'exists') else 'unknown'
    if exists:
        fp_count += 1
    else:
        missing_count += 1
print(f"  Files found in first 20: {fp_count}, missing: {missing_count}")