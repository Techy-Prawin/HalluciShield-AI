import sys
from pathlib import Path
repo = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
sys.path.insert(0, str(repo))
sys.path.insert(0, str(repo / 'ai-engine'))
from evaluation.dataset_b.evaluator import run_all_four_experiments, load_all_samples_info

samples = load_all_samples_info()
print(f'Sample count: {len(samples)}')

# Try running with limit
result = run_all_four_experiments(sample_limit=5, is_dry_run=False)
print(f'Processed: {result["full_ace"]["count"]} samples')