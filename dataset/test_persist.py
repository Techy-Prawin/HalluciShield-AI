import sys
sys.path.insert(0, '.')
from generate_dataset_b import *
import random
import os
from pathlib import Path
import time

random.seed(42)

from generate_dataset_b import compute_sha256, _load_existing_metadata, _append_metadata_atomic, SampleMetadata

print('Testing persistence with 3 samples...')
start = time.time()

# Clean up test directory
test_dir = Path("dataset/test_persist")
if test_dir.exists():
    import shutil
    shutil.rmtree(test_dir)

# Test positive sample generation with persistence
print('\nGenerating 3 positive samples with persistence...')
samples = []
for i in range(3):
    result = generate_sql_injection_sample('python', random.randint(0, 2**32-1))
    print(f'  Sample {i+1}: {result["code"][:80]}...')
    print(f'  Line: {result["vulnerable_line"]}, Sev: {result["severity"]}')
    
    # Create file path
    ext_map = {"python": "py", "javascript": "js", "typescript": "ts", "java": "java", "go": "go"}
    ext = ext_map.get('python', "py")
    file_name = f"test_sql_{i+1:03d}.{ext}"
    file_path = f"positive/cwe89/{file_name}"
    full_path = Path("dataset/test_persist") / file_path
    full_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write source file atomically
    temp_file = full_path.with_suffix('.tmp')
    temp_file.write_text(result["code"])
    temp_file.replace(full_path)
    
    # Compute hash
    sha256 = compute_sha256(result["code"])
    
    # Create metadata
    sample_id = f"DS-B-TEST-{i+1:04d}"
    from generate_dataset_b import SampleMetadata
    metadata = SampleMetadata(
        sample_id=f"DS-B-TEST-{i+1:04d}",
        language='python',
        cwe=result["cwe"],
        category="cwe89",
        label="positive",
        generator_model="qwen/qwen3.8-27b",
        generation_prompt="test",
        ground_truth=f"Test {result['vulnerability_type']} at line {result['vulnerable_line']}: {result['description']}",
        file_path=f"positive/cwe89/{file_name}",
        sha256=sha256,
        vulnerability_type=result["vulnerability_type"],
        severity=result["severity"],
        description=result["description"],
        temperature=0.2,
        max_tokens=1024,
    )
    
    # Test persistence
    csv_path = Path("dataset/test_persist/metadata.csv")
    json_path = Path("dataset/test_persist/metadata.json")
    
    # Load existing
    existing = _load_existing_metadata(csv_path)
    existing.append(metadata)
    _append_metadata_atomic(existing, csv_path, json_path)
    
    print(f'  Saved: {file_name} (hash: {sha256[:16]}...)')

# Verify persistence
print('\nVerifying persistence...')
existing = _load_existing_metadata(csv_path)
print(f'Loaded {len(existing)} samples from CSV')
for s in existing:
    print(f'  {s.sample_id}: {s.file_path} (hash: {s.sha256[:16]}...)')
    # Verify file exists
    full_path = Path("dataset/test_persist") / s.file_path
    if full_path.exists():
        actual_hash = compute_sha256(full_path.read_text())
        match = "OK" if actual_hash == s.sha256 else "MISMATCH"
        print(f'    File exists: YES, Hash: {match}')
    else:
        print(f'    File exists: NO')

# Test JSON
with open(json_path, 'r') as f:
    json_data = json.load(f)
print(f'\nJSON has {len(json_data)} entries')

elapsed = time.time() - start
print(f'\nTotal time: {elapsed:.1f}s')
print('Persistence test complete!')