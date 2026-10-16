import sys, time, subprocess, os
from pathlib import Path

sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')

from app.agents.semgrep_runner import SemgrepRunner

_REPO_ROOT = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
DATASET_ROOT = _REPO_ROOT / 'dataset' / 'dataset' / 'dataset-b'

# Load samples
from evaluation.dataset_b.dataset_loader import DatasetBLoader
loader = DatasetBLoader()
all_samples = loader.get_samples()

# Use first 3 samples for quick profiling
test_samples = all_samples[:3]

runner = SemgrepRunner()

print("=" * 70)
print("SEMGREP PROFILING - First 3 samples (quick)")
print("=" * 70)

for s_idx, sample in enumerate(test_samples):
    sample_id = sample['sample_id']
    file_path = DATASET_ROOT / sample['file_path']
    
    if not file_path.exists():
        print(f"Sample {sample_id}: file not found at {file_path}")
        continue
    
    # Profile Semgrep scan with 120s timeout
    start = time.time()
    try:
        findings, metadata = runner.run_scan(
            target_path=str(file_path),
            timeout_seconds=120,
        )
        elapsed = time.time() - start
        
        status = metadata.get('status', 'UNKNOWN')
        exit_code = metadata.get('exit_code', 'N/A')
        duration_ms = metadata.get('scan_duration_ms', int(elapsed * 1000))
        findings_count = len(findings)
        
        print(f"\nSample {sample_id}:")
        print(f"  Status: {status}")
        print(f"  Exit code: {exit_code}")
        print(f"  Duration: {duration_ms}ms ({duration_ms/1000:.2f}s)")
        print(f"  Findings: {findings_count}")
        
        if status == 'TIMEOUT':
            error = metadata.get('error', 'N/A')
            print(f"  Timeout error: {error}")
        
        if findings_count > 0:
            rule_ids = [f.rule_id for f in findings]
            print(f"  Rule IDs: {rule_ids[:10]}...")
            if len(rule_ids) > 10:
                print(f"  ... total {len(rule_ids)} rules")
    
    except Exception as e:
        elapsed = time.time() - start
        print(f"\nSample {sample_id}: ERROR after {elapsed:.1f}s: {type(e).__name__}: {e}")

print("\n" + "=" * 70)
print("DONE")
print("=" * 70)