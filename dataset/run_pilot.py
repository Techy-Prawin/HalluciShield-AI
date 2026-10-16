import sys
sys.path.insert(0, '.')
from generate_dataset_b import *
import random
import time

random.seed(42)

print('Generating 10 samples (7 positive + 3 negative)...')
start = time.time()

# Generate 7 positive + 3 negative samples
positive = generate_positive_samples()
print(f'Positive: {len(positive)}')
negative = generate_negative_samples()
print(f'Negative: {len(negative)}')

all_samples = positive + negative
print(f'Total: {len(all_samples)}')

# Check duplicates
unique_count, duplicate_count = check_duplicates(all_samples)
print(f'Unique: {unique_count}, Duplicates: {duplicate_count}')

elapsed = time.time() - start
print(f'Total time: {elapsed:.1f}s')