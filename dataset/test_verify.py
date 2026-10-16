import sys
sys.path.insert(0, '.')
from generate_dataset_b import *
import random
random.seed(42)

print('Testing one sample...')
result = generate_sql_injection_sample('python', 42)
print(f'Code: {result["code"][:100]}...')
print(f'Line: {result["vulnerable_line"]}')
print(f'Desc: {result["description"][:100]}...')