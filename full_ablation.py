import sys, time, json, subprocess
from pathlib import Path
from collections import Counter

sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')

from evaluation.dataset_b.dataset_loader import DatasetBLoader
from evaluation.dataset_b.ablation_config import PipelineConfig
from evaluation.dataset_b.full_ace_adapter import FullACEAdapter

# Load ALL Dataset B samples
loader = DatasetBLoader()
all_samples = loader.get_samples()
total_samples = len(all_samples)

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

# Tracking
results = []
prediction_counts = Counter()
stages_patterns = Counter()
findings_dist = Counter()
errors = 0
timeouts = 0
completed = 0

start_total = time.time()
start_msg = time.strftime('%Y-%m-%d %H:%M:%S')

print(f"Phase 5.6 Full Ablation Experiment")
print(f"Started: {start_msg}")
print(f"Samples: {total_samples}")
print(f"Configs: {len(CONFIGS)}")
print(f"Max experimental units: {total_samples * len(CONFIGS)}")
print("=" * 70)

# Process samples - skip those that consistently time out
sample_skip_count = 0
for s_idx, sample in enumerate(all_samples):
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
    
    if not file_path.exists():
        sample_skip_count += 1
        continue
    
    sample_ok = True
    config_results_for_sample = []
    
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
                'record_id': sample_id,
                'config_id': config_id,
                'file_path': str(file_path),
                'disk_sha256': sample.get('disk_sha256', ''),
                'prediction': predicted,
                'ground_truth': sample_info['ground_truth'],
                'execution_status': 'COMPLETED',
                'stage_trace': stages,
                'findings_count': findings,
                'latency_ms': int(s_elapsed * 1000),
                'error': None,
            })
            
            prediction_counts[predicted] += 1
            stages_patterns[(config_id, tuple(stages))] += 1
            findings_dist[findings] += 1
            completed += 1
            
            if (completed) % 100 == 0:
                print(f"  Completed {completed} experimental units...")
                
        except RuntimeError as e:
            if 'TIMEOUT' in str(e):
                timeouts += 1
                results.append({
                    'sample_id': sample_id,
                    'record_id': sample_id,
                    'config_id': config_id,
                    'file_path': str(file_path),
                    'disk_sha256': sample.get('disk_sha256', ''),
                    'prediction': None,
                    'ground_truth': sample_info['ground_truth'],
                    'execution_status': 'TIMEOUT',
                    'stage_trace': [],
                    'findings_count': 0,
                    'latency_ms': 0,
                    'error': str(e),
                })
            else:
                errors += 1
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
                    'findings_count': 0,
                    'latency_ms': 0,
                    'error': str(e),
                })
        except Exception as e:
            errors += 1
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
                'findings_count': 0,
                'latency_ms': 0,
                'error': str(e),
            })
    
    if (s_idx + 1) % 20 == 0:
        print(f"  Processed {s_idx + 1}/{total_samples} samples ({completed} completed, {timeouts} timeouts, {errors} errors)")

total_elapsed = time.time() - start_total

# Generate summary
print("=" * 70)
print(f"EXPERIMENT COMPLETE")
print(f"Started: {start_msg}")
print(f"Finished: {time.strftime('%Y-%m-%d %H:%M:%S')}")
print(f"Total time: {total_elapsed/60:.1f} minutes")
print(f"Total experimental units: {total_samples * len(CONFIGS)}")
print(f"Completed: {completed}")
print(f"Timeouts: {timeouts}")
print(f"Errors: {errors}")
print(f"Sample skip count: {sample_skip_count}")
print(f"Prediction distribution: {dict(prediction_counts)}")
print(f"Findings distribution: {dict(findings_dist)}")
print()

# Save raw results
output_dir = _REPO_ROOT / "evaluation" / "results" / "research" / "ablation500"
output_dir.mkdir(parents=True, exist_ok=True)

raw_path = output_dir / "raw_results.jsonl"
with open(raw_path, 'w') as f:
    for r in results:
        f.write(json.dumps(r) + '\n')
print(f"Raw results saved to {raw_path}")

# Per-config summary
print("Per-configuration prediction counts:")
for config_id in sorted(CONFIGS.keys()):
    config_results = [r for r in results if r['config_id'] == config_id and r['execution_status'] == 'COMPLETED']
    if config_results:
        pc = Counter(r['prediction'] for r in config_results)
        print(f"  {config_id}: {len(config_results)} completed, predictions={dict(pc)}")

# Save metrics
metrics = {
    'experiment_id': 'ablation500-empirical-evaluation',
    'start_time': start_msg,
    'end_time': time.strftime('%Y-%m-%d %H:%M:%S'),
    'total_samples': total_samples,
    'total_configurations': len(CONFIGS),
    'total_experimental_units': total_samples * len(CONFIGS),
    'completed_evaluations': completed,
    'timeout_evaluations': timeouts,
    'error_evaluations': errors,
    'sample_skip_count': sample_skip_count,
    'prediction_distribution': dict(prediction_counts),
    'findings_distribution': dict(findings_dist),
    'configurations': CONFIGS,
}
metrics_path = output_dir / 'metrics.json'
with open(metrics_path, 'w') as f:
    json.dump(metrics, f, indent=2)
print(f"Metrics saved to {metrics_path}")

print("=" * 70)
print("Phase 5.6 full ablation experiment terminating.")