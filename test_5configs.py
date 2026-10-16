import sys
import json
import time
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

configs_to_test = {
    "A": {"hallucination_detection": True, "dependency_analysis": True, "security_analysis": True,
          "risk_assessment": True, "patch_generation": True, "validation": True, "legacy_ace": True, "aece": True, "multi_patch": True},
    "B": {"hallucination_detection": False, "dependency_analysis": True, "security_analysis": True,
          "risk_assessment": True, "patch_generation": True, "validation": True, "legacy_ace": True, "aece": True, "multi_patch": True},
    "C": {"hallucination_detection": True, "dependency_analysis": False, "security_analysis": True,
          "risk_assessment": True, "patch_generation": True, "validation": True, "legacy_ace": True, "aece": True, "multi_patch": True},
    "D": {"hallucination_detection": True, "dependency_analysis": True, "security_analysis": False,
          "risk_assessment": True, "patch_generation": True, "validation": True, "legacy_ace": True, "aece": True, "multi_patch": True},
    "E": {"hallucination_detection": True, "dependency_analysis": True, "security_analysis": True,
          "risk_assessment": False, "patch_generation": True, "validation": True, "legacy_ace": True, "aece": True, "multi_patch": True},
}

print("Testing 5 configurations on sample", sample['sample_id'])
print("=" * 60)

for config_id, switches in configs_to_test.items():
    config = PipelineConfig(
        hallucination_detection=switches["hallucination_detection"],
        dependency_analysis=switches["dependency_analysis"],
        security_analysis=switches["security_analysis"],
        risk_assessment=switches["risk_assessment"],
        patch_generation=switches["patch_generation"],
        validation=switches["validation"],
        legacy_ace=switches["legacy_ace"],
        aece=switches["aece"],
        multi_patch=switches["multi_patch"],
    )
    adapter = FullACEAdapter(config=config)
    start = time.time()
    result = adapter.evaluate_sample(
        sample_info=sample_info,
        file_path=file_path,
    )
    elapsed = time.time() - start
    predicted = result.get('predicted_label')
    stages = result.get('stages_completed')
    findings = result.get('all_findings_count')
    print(f"  {config_id}: predicted={predicted}, stages={stages}, findings={findings}, elapsed={elapsed:.1f}s")