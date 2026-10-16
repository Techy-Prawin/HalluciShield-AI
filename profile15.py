import sys, time
from pathlib import Path

sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')

from app.agents.semgrep_runner import SemgrepRunner

_REPO_ROOT = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
DATASET_ROOT = _REPO_ROOT / 'dataset' / 'dataset' / 'dataset-b'

from evaluation.dataset_b.dataset_loader import DatasetBLoader
loader = DatasetBLoader()
all_samples = loader.get_samples()

# Profile first 15 samples
test_samples = all_samples[:15]

runner = SemgrepRunner()

print("=" * 70)
print("SEMGREP PROFILING - First 15 samples")
print("=" * 70)

total_elapsed = 0
timeout_count = 0
completed_count = 0
findings_counts = []

for s_idx, sample in enumerate(test_samples):
    sample_id = sample['sample_id']
    file_path = DATASET_ROOT / sample['file_path']
    
    if not file_path.exists():
        print(f"Sample {sample_id}: file not found at {file_path}")
        continue
    
    start = time.time()
    try:
        findings, metadata = runner.run_scan(
            target_path=str(file_path),
            timeout_seconds=120,
        )
        elapsed = time.time() - start
        total_elapsed += elapsed
        completed_count += 1
        fc = len(findings)
        findings_counts.append(fc)
        
        status = metadata.get('status', 'UNKNOWN')
        exit_code = metadata.get('exit_code', 'N/A')
        duration_ms = metadata.get('scan_duration_ms', int(elapsed * 1000))
        
        print(f"Sample {sample_id}: {elapsed:.1f}s ({duration_ms}ms) status={status} findings={fc}", end="")
        if status == 'TIMEOUT':
            print(f" ERROR={metadata.get('error', 'N/A')}", end="")
        print()
        
    except Exception as e:
        total_elapsed += 120  # assume timeout
        timeout_count += 1
        print(f"Sample {sample_id}: EXCEPTION {type(e).__name__}: {e}")

print("\n" + "=" * 70)
print(f"Completed: {completed_count}, Timeouts: {timeout_count}")
print(f"Total elapsed: {total_elapsed:.1f}s")
print(f"Avg per sample (completed): {total_elapsed/completed_count:.1f}s" if completed_count > 0 else "N/A")
print(f"Findings distribution: {Counter(findings_counts)}")

# Estimate full run times
if completed_count > 0:
    est_200 = total_elapsed / completed_count * 200
    est_4890 = total_elapsed / completed_count * 4890
    print(f"\nEst. 200-eval time: {est_200:.1f}s ({est_200/60:.1f} min)")
    print(f"Est. 4,890-eval time: {est_4890:.1f}s ({est_4890/3600:.1f} h)")