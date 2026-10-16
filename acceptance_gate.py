import sys, time, json
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
    "F": {"hallucination_detection": True, "dependency_analysis": True, "security_analysis": True,
          "risk_assessment": True, "patch_generation": False, "validation": True, "legacy_ace": True, "aece": True, "multi_patch": True},
    "G": {"hallucination_detection": True, "dependency_analysis": True, "security_analysis": True,
          "risk_assessment": True, "patch_generation": True, "validation": False, "legacy_ace": True, "aece": True, "multi_patch": True},
    "H": {"hallucination_detection": True, "dependency_analysis": True, "security_analysis": True,
          "risk_assessment": True, "patch_generation": True, "validation": True, "legacy_ace": False, "aece": True, "multi_patch": True},
    "I": {"hallucination_detection": True, "dependency_analysis": True, "security_analysis": True,
          "risk_assessment": True, "patch_generation": True, "validation": True, "legacy_ace": True, "aece": False, "multi_patch": True},
    "J": {"hallucination_detection": True, "dependency_analysis": True, "security_analysis": True,
          "risk_assessment": True, "patch_generation": True, "validation": True, "legacy_ace": True, "aece": True, "multi_patch": False},
}

# Use first 20 samples × 10 configs = 200 evaluations
test_samples = all_samples[:20]
total_evals = len(test_samples) * len(CONFIGS)
print(f"Running {total_evals} evaluations (20 samples × 10 configs)")
print("=" * 70)

results = []
prediction_counts = Counter()
stages_patterns = Counter()
findings_dist = Counter()
errors = 0
timeouts = 0
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
    
    if (s_idx + 1) % 5 == 0:
        elapsed_total = time.time() - start_total
        print(f"  Processed {s_idx + 1}/{len(test_samples)} samples ({elapsed_total:.1f}s elapsed, {len(results)} evaluations completed)")

total_elapsed = time.time() - start_total
num_complete = len([r for r in results if r.get('predicted_label') is not None and 'error' not in r])

print("=" * 70)
print(f"RESULTS: {num_complete} completed evaluations in {total_elapsed:.1f}s")
print(f"  Errors: {errors}")
print(f"  Timeouts: {timeouts}")
print(f"  Prediction distribution: {dict(prediction_counts)}")
print(f"  Findings distribution: {dict(findings_dist)}")
print()

# Per-config summary
print("Per-configuration results:")
for config_id in sorted(CONFIGS.keys()):
    config_results = [r for r in results if r['config_id'] == config_id and 'error' not in r and r.get('predicted_label') is not None]
    if config_results:
        pred_counts = Counter(r['predicted_label'] for r in config_results)
        stages_count = len(config_results)
        print(f"  {config_id}: {stages_count} evals, {total_elapsed/sstages_count:.1f}s avg, predictions={dict(pred_counts)}")

# Save raw results
output_dir = _REPO_ROOT / "evaluation" / "results" / "research" / "ablation500"
output_dir.mkdir(parents=True, exist_ok=True)
raw_path = output_dir / "raw_results_acceptance.jsonl"
with open(raw_path, 'w') as f:
    for r in results:
        f.write(json.dumps(r) + '\n')
print(f"\nRaw results saved to {raw_path}")

# Budget check
avg_time = total_elapsed / num_complete if num_complete > 0 else 0
print(f"\nAverage time per evaluation: {avg_time:.1f}s")
print(f"Estimated 200-eval time at this rate: {avg_time * 200:.1f}s ({avg_time * 200/60:.1f} min)")
print(f"Estimated 4,890-eval time at this rate: {avg_time * 4890:.1f}s ({avg_time * 4890/3600:.1f} h)")