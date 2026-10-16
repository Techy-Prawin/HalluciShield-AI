import sys, time
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

test_samples = all_samples[:3]
total_time = 0
count = 0
config_names = list(CONFIGS.keys())

for s_idx, sample in enumerate(test_samples):
    sample_id = sample['sample_id']
    sample_info = {'sample_id': sample_id, 'record_id': sample_id, 'label': sample['label'], 'category': sample['category'], 'cwe': sample['cwe'], 'language': sample['language'], 'ground_truth': sample.get('ground_truth', '')}
    file_path = DATASET_ROOT / sample['file_path']
    
    for config_id in config_names:
        start = time.time()
        config = PipelineConfig(**CONFIGS[config_id])
        adapter = FullACEAdapter(config=config)
        try:
            result = adapter.evaluate_sample(sample_info, file_path)
            elapsed = time.time() - start
            total_time += elapsed
            count += 1
            predicted = result.get('predicted_label')
            if (s_idx * 5 + config_names.index(config_id)) % 5 == 0:
                print('Sample %d, Config %s: %.1fs, prediction=%s' % (s_idx, config_id, elapsed, predicted))
        except Exception as e:
            elapsed = time.time() - start
            total_time += elapsed
            count += 1
            print('Sample %d, Config %s: %.1fs, ERROR: %s' % (s_idx, config_id, elapsed, type(e).__name__))

if count > 0:
    avg = total_time / count
    print('\nAverage time per evaluation: %.1fs' % avg)
    print('Estimated total for 200 evals: %.1fs (%.1f min)' % (avg * 200, avg * 200 / 60))
    print('Estimated total for 4890 evals: %.1fs (%.1f h)' % (avg * 4890, avg * 4890 / 3600))