import sys
sys.path.insert(0, '.')
from generate_dataset_b import *
import random
import time

random.seed(42)

print('Testing 7 positive + 3 negative samples...')
start = time.time()

# Test 7 positive samples (1 from each category)
print('\nPositive samples:')
positive_categories = list(POSITIVE_CATEGORIES.items())
for cat_key, cat_info in positive_categories[:7]:  # First 7 categories
    gen = CATEGORY_GENERATORS[cat_key]
    lang = random.choice(SUPPORTED_LANGUAGES)
    result = gen(lang, random.randint(0, 2**32-1))
    print(f'  {cat_key}: {result["code"][:80]}...')
    print(f'  Line: {result["vulnerable_line"]}, Sev: {result["severity"]}')

# Test 3 negative samples
print('\nNegative samples:')
for i in range(3):
    result = generate_clean_sample('python', random.randint(0, 2**32-1))
    print(f'  Clean {i+1}: {result["code"][:80]}...')

elapsed = time.time() - start
print(f'\nTotal time: {elapsed:.1f}s')
print('Pilot test complete!')