import sys, time, json
from pathlib import Path
from collections import Counter, defaultdict

sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')

from evaluation.dataset_b.dataset_loader import DatasetBLoader
from evaluation.dataset_b.ablation_config import PipelineConfig
from evaluation.dataset_b.full_ace_adapter import FullACEAdapter

_REPO_ROOT = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
DATASET_ROOT = _REPO_ROOT / 'dataset' / 'dataset' / 'dataset-b'

loader = DatasetBLoader()
all_samples = loader.get_samples()

# Compute experiment_id = sha256(file_path + ":" + disk_sha256) using actual disk SHA256
import hashlib
for s in all_samples:
    file_path = s['file_path']
    disk_path = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset\dataset-b') / file_path
    if disk_path.exists():
        with open(disk_path, 'rb') as f:
            disk_sha = hashlib.sha256(f.read()).hexdigest()
    else:
        disk_sha = s.get('sha256', '')
    exp_id = hashlib.sha256((file_path + ':' + disk_sha).encode()).hexdigest()
    s['experiment_id'] = exp_id

# Build mapping: experiment_id -> sample (first occurrence)
sample_by_exp = {}
for s in all_samples:
    eid = s['experiment_id']
    if eid not in sample_by_exp:
        sample_by_exp[eid] = s

unique_samples_list = list(sample_by_exp.values())
unique_exp_ids = set(sample_by_exp.keys())

print(f"Total samples: {len(all_samples)}")
print(f"Unique experiment_ids: {len(unique_exp_ids)}")

# Count duplicates
exp_id_counts = Counter(s['experiment_id'] for s in all_samples)
dup_exp = {eid: cnt for eid, cnt in exp_id_counts.items() if cnt > 1}
print(f"Duplicate experiment_id groups: {len(dup_exp)}")
for eid, cnt in list(dup_exp.items())[:3]:
    samples_with_eid = [s for s in all_samples if s['experiment_id'] == eid]
    print(f"  {eid[:8]}: {cnt} samples (sample_ids: {[s['sample_id'] for s in samples_with_eid[:2]]})")

# CONFIGURATIONS (A-J)
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

# State management
raw_results_path = _REPO_ROOT / "evaluation" / "results" / "research" / "ablation500" / "raw_results.jsonl"
checkpoint_path = _REPO_ROOT / "evaluation" / "results" / "research" / "ablation500" / "checkpoint.json"

# Load existing result keys for resume
existing_keys = set()
if raw_results_path.exists():
    with open(raw_results_path) as f:
        for line in f:
            r = json.loads(line)
            key = (r.get('record_id'), r.get('config_id'))
            existing_keys.add(key)
    print(f"Loaded {len(existing_keys)} existing result keys for resume")
else:
    print("No existing raw_results.jsonl - starting fresh")

# Load checkpoint if exists
completed_units = 0
if checkpoint_path.exists():
    with open(checkpoint_path) as f:
        cp = json.load(f)
    completed_units = cp.get('completed_units', 0)
    print(f"Checkpoint: {completed_units} units completed previously")

# Determine units to run: unique experiment_id × 10 configs, excluding already-done
units_to_run = []
for eid in unique_exp_ids:
    sample = sample_by_exp[eid]
    file_path = DATASET_ROOT / sample['file_path']
    if not file_path.exists():
        print(f"WARNING: File not found: {file_path}")
        continue
    for config_id in CONFIGS.keys():
        key = (eid, config_id)
        if key not in existing_keys:
            units_to_run.append((eid, config_id, sample, file_path))

# Deduplicate units (shouldn't be needed since we iterate unique_exp_ids once per config)
seen_units = set()
unique_units = []
for eid, config_id, sample, file_path in units_to_run:
    key = (eid, config_id)
    if key not in seen_units:
        seen_units.add(key)
        unique_units.append((eid, config_id, sample, file_path))

print(f"\nTotal unique units: {len(unique_units)}")
print(f"Already completed: {len(existing_keys)}")
new_units = [u for u in unique_units if (u[0], u[1]) not in existing_keys]
print(f"New units to run: {len(new_units)}")

# Budget and timing
avg_time_per_eval = 21.0  # seconds from acceptance test
estimated_total_s = len(new_units) * avg_time_per_eval
estimated_hours = estimated_total_s / 3600
print(f"\nEstimated time per evaluation: {avg_time_per_eval}s (from acceptance test)")
print(f"Estimated total time for new units: {estimated_total_s:.1f}s ({estimated_total_s/3600:.1f} hours)")
print(f"Using single worker (stable execution)")

# Run the units
if len(new_units) > 0:
    print(f"\n--- Starting full ablation run ---")
    print(f"Units: {len(new_units)}, Already done: {len(existing_keys)}")
    
    results = []
    start_total = time.time()
    
    # Process units (single worker for stability)
    for i, (eid, config_id, sample, file_path) in enumerate(unique_units):
        # Skip if already in results (from existing or earlier in this run)
        if (eid, config_id) in existing_keys:
            continue
        
        sample_info = {
            'sample_id': sample['sample_id'],
            'record_id': eid,
            'label': sample['label'],
            'category': sample['category'],
            'cwe': sample['cwe'],
            'language': sample['language'],
            'ground_truth': sample.get('ground_truth', ''),
        }
        
        config = PipelineConfig(**CONFIGS[config_id])
        adapter = FullACEAdapter(config=config)
        
        try:
            s_start = time.time()
            result = adapter.evaluate_sample(sample_info=sample_info, file_path=file_path)
            s_elapsed = time.time() - s_start
            
            predicted = result.get('predicted_label')
            stages = result.get('stages_completed', [])
            findings = result.get('all_findings_count', 0)
            
            result_entry = {
                'record_id': eid,
                'sample_id': sample['sample_id'],
                'config_id': config_id,
                'file_path': str(file_path),
                'disk_sha256': sample.get('sha256', ''),
                'prediction': predicted,
                'ground_truth': sample_info['ground_truth'],
                'execution_status': 'COMPLETED',
                'stage_trace': stages,
                'findings_count': findings,
                'latency_ms': int(s_elapsed * 1000),
                'provenance': 'REAL',
                'error': None,
            }
            
            results.append(result_entry)
            existing_keys.add((eid, config_id))
            completed_units += 1
            
            # Save checkpoint every 50 units
            if completed_units % 50 == 0:
                with open(checkpoint_path, 'w') as f:
                    json.dump({
                        'completed_units': completed_units,
                        'elapsed_s': time.time() - start_total,
                        'throughput_s_per_unit': (time.time() - start_total) / completed_units if completed_units > 0 else 0
                    }, f, indent=2)
                print(f"Checkpoint: {completed_units} units done, {time.time() - start_total:.1f}s elapsed")
            
            # Progress reporting every 20 units
            if (i + 1) % 20 == 0 or (i + 1) == len(unique_units):
                pct = 100 * (i + 1) / len(unique_units)
                elapsed = time.time() - start_total
                rate = (i + 1) / elapsed * 60 if elapsed > 0 else 0
                remaining = len(unique_units) - (i + 1)
                eta_s = remaining / rate if rate > 0 else 0
                print(f"Progress: {i+1}/{len(unique_units)} ({pct:.1f}%), "
                      f"{elapsed:.1f}s elapsed, {rate:.1f}/min rate, ETA {eta_s/60:.1f} min")
                
        except Exception as e:
            completed_units += 1
            print(f"Error on unit {i+1} (eid={eid[:8]}..., config={config_id}): {type(e).__name__}: {e}")
    
    total_elapsed = time.time() - start_total
    
    # Write all results to raw_results.jsonl
    # First, save any previously existing results, then append new ones
    all_results = []
    
    # Load existing results
    if raw_results_path.exists():
        with open(raw_results_path) as f:
            for line in f:
                all_results.append(json.loads(line))
    
    # Append new results
    all_results.extend(results)
    
    # Write complete raw_results.jsonl
    with open(raw_results_path, 'w') as f:
        for r in all_results:
            f.write(json.dumps(r) + '\n')
    
    print(f"\n=== ABLATION COMPLETE ===")
    print(f"Total unique units: {len(unique_units)}")
    print(f"New results written: {len(results)}")
    print(f"Total in raw_results.jsonl: {len(all_results)}")
    print(f"Total elapsed time: {total_elapsed:.1f}s ({total_elapsed/3600:.1f}h)")
    
    # Save final checkpoint
    with open(checkpoint_path, 'w') as f:
        json.dump({
            'completed_units': completed_units,
            'total_unique': len(unique_units),
            'elapsed_s': total_elapsed,
            'raw_results_file': str(raw_results_path),
            'total_raw_results': len(all_results)
        }, f, indent=2)
    
    # Summary
    pred_counts = Counter(r['prediction'] for r in results if r['prediction'] is not None)
    print(f"\nPrediction distribution: {dict(pred_counts)}")
    
    # Count by config
    config_preds = defaultdict(Counter)
    for r in results:
        config_preds[r['config_id']][r['prediction']] += 1
    print("\nPer-configuration predictions:")
    for cfg in sorted(CONFIGS.keys()):
        if cfg in config_preds:
            print(f"  {cfg}: {dict(config_preds[cfg])}")
    
else:
    print("\n=== ALL UNITS ALREADY COMPLETED ===")
    print(f"All {len(unique_units)} unique units already in raw_results.jsonl")