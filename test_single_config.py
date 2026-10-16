import sys
import json
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
from pathlib import Path
from evaluation.dataset_b.dataset_loader import DatasetBLoader
from evaluation.dataset_b.ablation_config import PipelineConfig
from evaluation.dataset_b.full_ace_adapter import FullACEAdapter

# Setup
loader = DatasetBLoader()
samples = loader.get_samples()
sample = samples[0]  # DS-B-0002

_REPO_ROOT = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
DATASET_ROOT = _REPO_ROOT / 'dataset' / 'dataset' / 'dataset-b'
file_path = DATASET_ROOT / sample['file_path']

sample_info = {
    'sample_id': sample['sample_id'],
    'record_id': sample['sample_id'],
    'label': sample['label'],
    'category': sample['category'],
    'cwe': sample['cwe'],
    'language': sample['language'],
    'ground_truth': sample.get('ground_truth', ''),
}

# Test just config A (all enabled) first
print("Testing config A (ALL ENABLED)")
config = PipelineConfig()  # All enabled
adapter = FullACEAdapter(config=config)
import time
start = time.time()
result = adapter.evaluate_sample(
    sample_info=sample_info,
    file_path=file_path,
)
elapsed = time.time() - start
predicted = result.get('predicted_label')
stages = result.get('stages_completed')
findings = result.get('all_findings_count')
print(f"  predicted={predicted}, stages={stages}, findings={findings}, elapsed={elapsed:.1f}s")