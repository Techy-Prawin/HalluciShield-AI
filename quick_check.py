import sys, time
from pathlib import Path
from collections import Counter

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
results = []
pred_counts = Counter()
start = time.time()

for sample in test_samples:
    sample_id = sample['sample_id']
    sample_info = {'sample_id': sample_id, 'record_id': sample_id, 'label': sample['label'], 'category': sample['category'], 'cwe': sample['cwe'], 'language': sample['language'], 'ground_truth': sample.get('ground_truth', '')}
    file_path = DATASET_ROOT / sample['file_path']
    
    for config_id in ['A', 'B', 'C', 'D', 'E']:
        config = PipelineConfig(**CONFIGS[config_id])
        adapter = FullACEAdapter(config=config)
        try:
            s_start = time.time()
            result = adapter.evaluate_sample(sample_info, file_path)
            s_elapsed = time.time() - s_start
            predicted = result.get('predicted_label')
            stages = result.get('stages_completed', [])
            findings = result.get('all_findings_count', 0)
            results.append({'sample_id': sample_id, 'config_id': config_id, 'predicted': predicted, 'stages': stages, 'findings': findings, 'elapsed': s_elapsed})
            pred_counts[predicted] += 1
        except Exception as e:
            results.append({'sample_id': sample_id, 'config_id': config_id, 'predicted': 'ERROR', 'stages': [], 'findings': 0, 'elapsed': 0, 'error': str(e)})

total = time.time() - start
print(f'3 samples x 5 configs = {len(results)} evals in {total:.1f}s')
print(f'Avg: {total/len(results):.1f}s per eval')
print(f'Predictions: {dict(pred_counts)}')
print('First 5 results:')
for r in results[:5]:
    sid = r['sample_id']
    cid = r['config_id']
    pred = r['predicted']
    elp = r['elapsed']
    st = r['stages']
    fi = r['findings']
    print(f'  {sid} {cid}: {pred} ({elp:.1f}s, stages={st}, findings={fi})')