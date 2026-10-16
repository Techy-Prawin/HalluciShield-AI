#!/usr/bin/env python3
"""Test script to verify Semgrep baseline."""
import sys, os
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
os.environ['LLM_API_KEY'] = ''
from evaluation.dataset_b.evaluator import load_all_samples_info, run_semgrep_baseline

samples = load_all_samples_info()
# Run semgrep on first 3 samples only
result = run_semgrep_baseline(samples[:3])
print(f'Semgrep baseline: {len(result["results"])} samples')
r = result['results'][0]
print(f'Sample 0: label={r["label"]}, predicted={r["predicted_label"]}, detection_correct={r["detection_correct"]}')
print(f'  scanner_result: {r["scanner_result"]}')
print(f'  finding_count: {r["finding_count"]}')
print(f'  confidence: {r["confidence"]}')