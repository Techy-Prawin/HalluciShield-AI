import sys
import json
import time
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
    "A": {"hallucination_detection": True, "dependency_analysis": True, "security_analysis": True,
          "risk_assessment": True, "patch_generation": True, "validation": True, "legacy_ace": True, "aece": True, "multi_patch": True},
    "B": {"hallucination_detection": False, "dependency_analysis": True, "security_analysis": True,
          "risk_assessment": True, "patch_generation": True, "validation": True, "legacy_ace": True, "aece": True, "multi_patch": True},
    "C": {"hallucination_detection": True, "dependency_analysis": False, "security_analysis": True,
          "risk_assessment": True, "patch_generation": True, "validation": True, "legacy_ace": True, "aece": True, "multi_patch": True},
    "D": {"hallucination_detection": True, "dependency_analysis": True, "security_analysis": False,
          "risk_assessment": True, "patch_generation": True, "validation": True, "legacy_ace": True, "aece": True, "multi_patch": True},
}

# Test each sample with all 4 configs, timeout 30s per eval
working_samples = []
for sample in all_samples[:30]:  # Test first 30 samples
    file_path = DATASET_ROOT / sample['file_path']
    if not file_path.exists():
        continue
    
    sample_info = {
        'sample_id': sample['sample_id'],
        'record_id': sample['sample_id'],
        'label': sample['label'],
        'category': sample['category'],
        'cwe': sample['cwe'],
        'language': sample['language'],
        'ground_truth': sample.get('ground_truth', ''),
    }
    
    sample_works = True
    for config_id, cfg_sw in CONFIGS.items():
        config = PipelineConfig(
            hallucination_detection=cfg_sw["hallucination_detection"],
            dependency_analysis=cfg_sw["dependency_analysis"],
            security_analysis=cfg_sw["security_analysis"],
            risk_assessment=cfg_sw["risk_assessment"],
            patch_generation=cfg_sw["patch_generation"],
            validation=cfg_sw["validation"],
            legacy_ace=cfg_sw["legacy_ace"],
            aece=cfg_sw["aece"],
            multi_patch=cfg_sw["multi_patch"],
        )
        adapter = FullACEAdapter(config=config)
        try:
            start = time.time()
            result = adapter.evaluate_sample(
                sample_info=sample_info,
                file_path=file_path,
            )
            elapsed = time.time() - start
            if elapsed > 30:
                sample_works = False
                break
        except RuntimeError as e:
            if "TIMEOUT" in str(e):
                sample_works = False
                break
            raise
    
    if sample_works:
        working_samples.append(sample)
        print(f"  {sample['sample_id']}: WORKS ({len(working_samples)} total)")
    else:
        print(f"  {sample['sample_id']}: TIMEOUT/SKIP")

print(f"\nWorking samples: {len(working_samples)}")
print("Using these for runtime test")