import sys
sys.path.insert(0, '.')
from generate_dataset_b import *
import random
import time

random.seed(42)

print('Starting FULL Dataset B generation (500 samples)...')
start = time.time()

# Generate all samples
positive = generate_positive_samples()
print(f'Positive: {len(positive)}')

negative = generate_negative_samples()
print(f'Negative: {len(negative)}')

all_samples = positive + negative
print(f'Total: {len(all_samples)}')

# Check duplicates
unique_count, duplicate_count = check_duplicates(all_samples)
print(f'Unique: {unique_count}, Duplicates: {duplicate_count}')

# Write metadata
dataset_dir = Path("dataset/dataset-b")
csv_path = dataset_dir / "metadata.csv"
json_path = Path("dataset/dataset-b/metadata.json")

print(f"\nWriting metadata to {csv_path}...")
write_metadata_csv(all_samples, csv_path)

with open(json_path, 'w') as f:
    json.dump([asdict(s) for s in all_samples], f, indent=2, default=str)

elapsed = time.time() - start
print(f'\nTotal time: {elapsed:.1f}s ({elapsed/60:.1f} minutes)')