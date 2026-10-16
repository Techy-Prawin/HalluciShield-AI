import sys
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
import json
from pathlib import Path
from evaluation.dataset_b.dataset_loader import DatasetBLoader
from evaluation.dataset_b.ablation_config import PipelineConfig
from evaluation.dataset_b.full_ace_adapter import FullACEAdapter

# Load one sample
loader = DatasetBLoader()
samples = loader.get_samples()
sample = samples[0]
print('Sample ID:', sample['sample_id'])
print('File path:', sample['file_path'])

# Check file exists
_REPO_ROOT = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
DATASET_ROOT = _REPO_ROOT / 'dataset' / 'dataset' / 'dataset-b'
file_path = DATASET_ROOT / sample['file_path']
print('File exists:', file_path.exists())

# Try running one config
config = PipelineConfig()  # All enabled
adapter = FullACEAdapter(config=config)
result = adapter.evaluate_sample(
    sample_info={
        'sample_id': sample['sample_id'],
        'record_id': sample['sample_id'],
        'label': sample['label'],
        'category': sample['category'],
        'cwe': sample['cwe'],
        'language': sample['language'],
        'ground_truth': sample.get('ground_truth', ''),
    },
    file_path=file_path,
)
print('Result status:', result.get('predicted_label'))
print('Stages completed:', result.get('stages_completed'))
print('All findings count:', result.get('all_findings_count'))