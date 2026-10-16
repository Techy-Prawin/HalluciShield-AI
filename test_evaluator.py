#!/usr/bin/env python3
"""Test script to verify evaluator loading."""
import sys
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
from evaluation.dataset_b.evaluator import load_all_samples_info

samples = load_all_samples_info()
print(f'Loaded {len(samples)} samples')
first = samples[0]
rid = first['record_id'][:16]
print(f'First sample record_id: {rid}...')
print(f'First sample label: {first["label"]}')
print(f'First sample category: {first["category"]}')
print(f'First sample language: {first["language"]}')
print(f'First sample cwe: {first["cwe"]}')
print(f'First sample file_path: {first["file_path"]}')