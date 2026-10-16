import sys
import json
import time
from pathlib import Path
from collections import Counter

sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')

from evaluation.dataset_b.dataset_loader import DatasetBLoader
from evaluation.dataset_b.ablation_config import PipelineConfig
from evaluation.dataset_b.full_ace_adapter import FullACEAdapter

# Setup
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

# Use only samples where all 4 configs complete within 60s
# Filter samples based on prior testing: A works, D sometimes fast, B/C work
completed_samples = []
skipped = 0

for sample in all_samples:
    file_path = DATASET_ROOT / sample['file_path']
    if not file_path.exists():
        skipped += 1
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
    
    sample_ok = True
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
            if elapsed > 60:
                sample_ok = False
                break
        except Exception as e:
            sample_ok = False
            break
    
    if sample_ok:
        completed_samples.append(sample)
    else:
        skipped += 1

print(f"Completed samples: {len(completed_samples)} out of {len(all_samples)} (skipped: {skipped})")
print(f"Using {len(completed_samples)} samples for runtime test")
print("=" * 70)

# Now run 5 of the completed samples × 4 configs = 20 evaluations
test_samples = completed_samples[:5]

results = []
prediction_counts = Counter()
stages_patterns = Counter()
findings_dist = Counter()
errors = 0

start_total = time.time()

for s_idx, sample in enumerate(test_samples):
    sample_id = sample['sample_id']
    sample_info = {
        'sample_id': sample_id,
        'record_id': sample_id,
        'label': sample['label'],
        'category': sample['category'],
        'cwe': sample['cwe'],
        'language': sample['language'],
        'ground_truth': sample.get('ground_truth', ''),
    }
    file_path = DATASET_ROOT / sample['file_path']
    
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
            s_start = time.time()
            result = adapter.evaluate_sample(
                sample_info=sample_info,
                file_path=file_path,
            )
            s_elapsed = time.time() - s_start
            
            predicted = result.get('predicted_label')
            stages = result.get('stages_completed', [])
            findings = result.get('all_findings_count', 0)
            
            results.append({
                'sample_id': sample_id,
                'config_id': config_id,
                'predicted_label': predicted,
                'stages_completed': stages,
                'all_findings_count': findings,
                'elapsed': s_elapsed,
            })
            
            prediction_counts[predicted] += 1
            stages_patterns[(config_id, tuple(stages))] += 1
            findings_dist[findings] += 1
            
        except Exception as e:
            errors += 1
            results.append({
                'sample_id': sample_id,
                'config_id': config_id,
                'predicted_label': 'ERROR',
                'stages_completed': [],
                'all_findings_count': 0,
                'elapsed': 0,
                'error': str(e),
            })

total_elapsed = time.time() - start_total
num_evals = len([r for r in results if 'error' not in r])

print("=" * 70)
print(f"RESULTS: {num_evals} evaluations in {total_elapsed:.1f}s")
print(f"  Errors: {errors}")
print(f"  Prediction distribution: {dict(prediction_counts)}")
print(f"  Findings distribution: {dict(findings_dist)}")
print()

# Per-config summary
print("Per-configuration results:")
for config_id in sorted(CONFIGS.keys()):
    config_results = [r for r in results if r['config_id'] == config_id and 'error' not in r]
    if config_results:
        pred_counts = Counter(r['predicted_label'] for r in config_results)
        print(f"  {config_id}: {len(config_results)} evals, predictions={dict(pred_counts)}")