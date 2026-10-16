import sys, time
from pathlib import Path

sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')

from evaluation.dataset_b.dataset_loader import DatasetBLoader
from evaluation.dataset_b.ablation_config import PipelineConfig
from evaluation.dataset_b.full_ace_adapter import FullACEAdapter

_REPO_ROOT = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
DATASET_ROOT = _REPO_ROOT / 'dataset' / 'dataset' / 'dataset-b'

loader = DatasetBLoader()
all_samples = loader.get_samples()

CONFIGS = {
    'A': {'hallucination_detection': True, 'dependency_analysis': True, 'security_analysis': True, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True},
    'B': {'hallucination_detection': False, 'dependency_analysis': True, 'security_analysis': True, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True},
    'C': {'hallucination_detection': True, 'dependency_analysis': False, 'security_analysis': True, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True},
    'D': {'hallucination_detection': True, 'dependency_analysis': True, 'security_analysis': False, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True},
    'E': {'hallucination_detection': True, 'dependency_analysis': True, 'security_analysis': True, 'risk_assessment': False, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True},
}

# Use first 3 samples × 5 configs
test_samples = all_samples[:3]

total_start = time.time()
total_elapsed = 0
count = 0

for s_idx, sample in enumerate(test_samples):
    sample_id = sample['sample_id']
    sample_info = {'sample_id': sample_id, 'record_id': sample_id, 'label': sample['label'], 'category': sample['category'], 'cwe': sample['cwe'], 'language': sample['language'], 'ground_truth': sample.get('ground_truth', '')}
    file_path = DATASET_ROOT / sample['file_path']
    
    for config_id in ['A', 'B', 'C', 'D', 'E']:
        start = time.time()
        config = PipelineConfig(**CONFIGS[config_id])
        adapter = FullACEAdapter(config=config)
        try:
            result = adapter.evaluate_sample(sample_info, file_path)
            elapsed = time.time() - start
            total_elapsed += elapsed
            count += 1
            predicted = result.get('predicted_label')
            if count % 5 == 1:
                print(f"Sample {sample_id}, Config {config_id}: {elapsed:.1f}s, prediction={predicted}")
        except Exception as e:
            elapsed = time.time() - start
            total_elapsed += elapsed
            count += 1
            print(f"Sample {sample_id}, Config {config_id}: {elapsed:.1f}s, ERROR: {type(e).__name__}")

total_elapsed = time.time() - total_start
print(f"\nTotal: {count} evaluations in {total_elapsed:.1f}s")
print(f"Avg per evaluation: {total_elapsed/count:.1f}s" if count > 0 else "N/A")
if count > 0:
    est_200 = total_elapsed / count * 200
    est_4890 = total_elapsed / count * 4890
    print(f"Est. 200-eval time: {est_200:.1f}s ({est_200/60:.1f} min)")
    print(f"Est. 4,890-eval time: {est_4890:.1f}s ({est_4890/3600:.1f} h)")