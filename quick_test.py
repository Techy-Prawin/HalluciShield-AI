import sys, time
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
from pathlib import Path
from evaluation.dataset_b.dataset_loader import DatasetBLoader
from evaluation.dataset_b.ablation_config import PipelineConfig
from evaluation.dataset_b.full_ace_adapter import FullACEAdapter

loader = DatasetBLoader()
sample = loader.get_samples()[0]
_REPO_ROOT = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
DATASET_ROOT = _REPO_ROOT / 'dataset' / 'dataset' / 'dataset-b'
file_path = DATASET_ROOT / sample['file_path']

sample_info = {'sample_id': sample['sample_id'], 'record_id': sample['sample_id'], 'label': sample['label'], 'category': sample['category'], 'cwe': sample['cwe'], 'language': sample['language'], 'ground_truth': sample.get('ground_truth', '')}

CONFIGS = {
    'A': {'hallucination_detection': True, 'dependency_analysis': True, 'security_analysis': True, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True},
    'B': {'hallucination_detection': False, 'dependency_analysis': True, 'security_analysis': True, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True},
    'C': {'hallucination_detection': True, 'dependency_analysis': False, 'security_analysis': True, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True},
    'D': {'hallucination_detection': True, 'dependency_analysis': True, 'security_analysis': False, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True},
    'E': {'hallucination_detection': True, 'dependency_analysis': True, 'security_analysis': True, 'risk_assessment': False, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True},
}

for cid, sw in CONFIGS.items():
    config = PipelineConfig(**sw)
    adapter = FullACEAdapter(config=config)
    start = time.time()
    result = adapter.evaluate_sample(sample_info, file_path)
    elapsed = time.time() - start
    predicted = result['predicted_label']
    stages = result['stages_completed']
    findings = result['all_findings_count']
    print(cid, predicted, stages, findings, f'{elapsed:.1f}s')