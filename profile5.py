import sys, time
from pathlib import Path

sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')

from app.agents.semgrep_runner import SemgrepRunner

_REPO_ROOT = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
DATASET_ROOT = _REPO_ROOT / 'dataset' / 'dataset' / 'dataset-b'

from evaluation.dataset_b.dataset_loader import DatasetBLoader
loader = DatasetBLoader()
all_samples = loader.get_samples()

test_samples = all_samples[:5]

runner = SemgrepRunner()

print("SEMGREP PROFILING - First 5 samples")
print("=" * 60)

total_elapsed = 0
completed = 0
timeouts = 0
findings_counts = []

for s_idx, sample in enumerate(test_samples):
    sample_id = sample['sample_id']
    file_path = DATASET_ROOT / sample['file_path']
    
    if not file_path.exists():
        print(f"Sample {sample_id}: file not found")
        continue
    
    start = time.time()
    try:
        findings, metadata = runner.run_scan(
            target_path=str(file_path),
            timeout_seconds=120,
        )
        elapsed = time.time() - start
        total_elapsed += elapsed
        completed += 1
        fc = len(findings)
        findings_counts.append(fc)
        
        status = metadata.get('status', 'UNKNOWN')
        exit_code = metadata.get('exit_code', 'N/A')
        duration_ms = metadata.get('scan_duration_ms', int(elapsed * 1000))
        
        print(f"{sample_id}: {elapsed:.1f}s ({duration_ms}ms) status={status} findings={fc}", end="")
        if status == 'TIMEOUT':
            print(f" error={metadata.get('error', 'N/A')}", end="")
        print()
        
    except Exception as e:
        total_elapsed += 120
        timeouts += 1
        print(f"{sample_id}: EXCEPTION {type(e).__name__}: {e}")

print("\n" + "-" * 60)
print(f"Completed: {completed}, Timeouts: {timeouts}")
print(f"Total elapsed: {total_elapsed:.1f}s")
if completed > 0:
    print(f"Avg per sample: {total_elapsed/completed:.1f}s")
    print(f"Findings distribution: {Counter(findings_counts)}")