import sys, time, json, subprocess, os
from pathlib import Path
from collections import Counter

sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\ai-engine')
sys.path.insert(0, r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')

from app.agents.semgrep_runner import SemgrepRunner

_REPO_ROOT = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
DATASET_ROOT = _REPO_ROOT / 'dataset' / 'dataset' / 'dataset-b'

# Load samples
from evaluation.dataset_b.dataset_loader import DatasetBLoader
loader = DatasetBLoader()
all_samples = loader.get_samples()

# Use first 10 samples for profiling
test_samples = all_samples[:10]

runner = SemgrepRunner()

print("=" * 70)
print("SEMGREP PROFILING - First 10 samples")
print("=" * 70)

for s_idx, sample in enumerate(test_samples):
    sample_id = sample['sample_id']
    file_path = DATASET_ROOT / sample['file_path']
    
    if not file_path.exists():
        print(f"Sample {sample_id}: file not found at {file_path}")
        continue
    
    code = file_path.read_text(encoding="utf-8", errors="replace")
    lang = sample['language']
    file_size = len(code)
    
    print(f"\n--- Sample {sample_id} ---")
    print(f"  Language: {lang}")
    print(f"  File size: {file_size} bytes ({file_size/1024:.1f} KB)")
    
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
        
        print(f"  Status: {status}")
        print(f"  Exit code: {exit_code}")
        print(f"  Duration: {duration_ms}ms ({duration_ms/1000:.1f}s)")
        print(f"  Findings: {findings_count}")
        
        # Show error if timeout
        if status == 'TIMEOUT':
            error = metadata.get('error', 'N/A')
            print(f"  Timeout error: {error}")
        
        # Show finding rule IDs if any
        if findings_count > 0:
            rule_ids = [f.rule_id for f in findings[:5]]
            print(f"  Rule IDs (first 5): {rule_ids}")
            if findings_count > 5:
                print(f"  ... and {findings_count - 5} more")
    
    except Exception as e:
        elapsed = time.time() - start
        print(f"  ERROR after {elapsed:.1f}s: {type(e).__name__}: {e}")

# Summary
print("\n" + "=" * 70)
print("PROFILING SUMMARY")
print("=" * 70)

total_elapsed = 0
total_findings = 0
timeout_count = 0
sample_count = 0

for s_idx, sample in enumerate(test_samples):
    sample_id = sample['sample_id']
    file_path = DATASET_ROOT / sample['file_path']
    if not file_path.exists():
        continue
    
    start = time.time()
    try:
        findings, metadata = runner.run_scan(
            target_path=str(file_path),
            timeout_seconds=120,
        )
        elapsed = time.time() - start
        total_elapsed += elapsed
        total_findings += len(findings)
        sample_count += 1
    except Exception as e:
        total_elapsed += 120  # timed out
        timeout_count += 1
        sample_count += 1

if sample_count > 0:
    print(f"Total samples profiled: {sample_count}")
    print(f"Total elapsed time: {total_elapsed:.1f}s")
    print(f"Avg per sample: {total_elapsed/sample_count:.1f}s")
    print(f"Total findings: {total_findings}")
    print(f"Timeouts: {timeout_count}")
    if sample_count > 0:
        est_200 = total_elapsed / sample_count * 200
        est_4890 = total_elapsed / sample_count * 4890
        print(f"Est. 200-eval time: {est_200:.1f}s ({est_200/60:.1f} min)")
        print(f"Est. 4,890-eval time: {est_4890:.1f}s ({est_4890/3600:.1f} h)")