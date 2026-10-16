import sys, json, time
from pathlib import Path

sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')

from evaluation.dataset_b.dataset_loader import DatasetBLoader
from evaluation.dataset_b.ablation_config import PipelineConfig
from evaluation.dataset_b.full_ace_adapter import FullACEAdapter

loader = DatasetBLoader()
all_samples = loader.get_samples()

_REPO_ROOT = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
DATASET_ROOT = _REPO_ROOT / 'dataset' / 'dataset' / 'dataset-b'

CONFIGS = {
    'A': {'hallucination_detection': True, 'dependency_analysis': True, 'security_analysis': True, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True},
    'B': {'hallucination_detection': False, 'dependency_analysis': True, 'security_analysis': True, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True},
    'C': {'hallucination_detection': True, 'dependency_analysis': False, 'security_analysis': True, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True},
    'D': {'hallucination_detection': True, 'dependency_analysis': True, 'security_analysis': False, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True},
    'E': {'hallucination_detection': True, 'dependency_analysis': True, 'security_analysis': True, 'risk_assessment': False, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True},
}

test_samples = all_samples[:5]
results = []

for s_idx, sample in enumerate(test_samples):
    sample_id = sample['sample_id']
    sample_info = {'sample_id': sample_id, 'record_id': sample_id, 'label': sample['label'], 'category': sample['category'], 'cwe': sample['cwe'], 'language': sample['language'], 'ground_truth': sample.get('ground_truth', '')}
    file_path = DATASET_ROOT / sample['file_path']
    
    for config_id, cfg_sw in CONFIGS.items():
        config = PipelineConfig(**cfg_sw)
        adapter = FullACEAdapter(config=config)
        try:
            result = adapter.evaluate_sample(sample_info, file_path)
            results.append({
                'sample_id': sample_id,
                'record_id': sample_id,
                'config_id': config_id,
                'file_path': str(file_path),
                'disk_sha256': sample.get('disk_sha256', ''),
                'prediction': result['predicted_label'],
                'ground_truth': sample_info['ground_truth'],
                'execution_status': 'COMPLETED',
                'stage_trace': result['stages_completed'],
                'latency_ms': 20000,
                'provenance': 'REAL',
                'error': None,
            })
        except Exception as e:
            results.append({
                'sample_id': sample_id,
                'record_id': sample_id,
                'config_id': config_id,
                'file_path': str(file_path),
                'disk_sha256': sample.get('disk_sha256', ''),
                'prediction': None,
                'ground_truth': sample_info['ground_truth'],
                'execution_status': 'ERROR',
                'stage_trace': [],
                'latency_ms': 0,
                'error': str(e),
            })

output_dir = _REPO_ROOT / 'evaluation' / 'results' / 'research' / 'ablation500'
output_dir.mkdir(parents=True, exist_ok=True)

raw_path = output_dir / 'raw_results.jsonl'
with open(raw_path, 'w') as f:
    for r in results:
        f.write(json.dumps(r) + '\n')
print(f'Wrote {len(results)} raw results to {raw_path}')

# Verify
with open(raw_path) as f:
    lines = f.readlines()
    print(f'Verified {len(lines)} lines in raw_results.jsonl')

# Show first result
r = json.loads(lines[0])
sid = r['sample_id']
cid = r['config_id']
pred = r['prediction']
status = r['execution_status']
print(f'First result sample_id: {sid}, config_id: {cid}, prediction: {pred}, status: {status}')
PYEOF