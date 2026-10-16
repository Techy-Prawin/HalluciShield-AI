import sys
sys.path.insert(0, '.')
from generate_dataset_b import *
import random
import time
from pathlib import Path

random.seed(42)

print('Testing resume capability...')

# First, generate 2 samples and persist them
test_dir = Path("dataset/test_resume")
if test_dir.exists():
    import shutil
    shutil.rmtree(test_dir)

test_dir.mkdir(parents=True, exist_ok=True)
(test_dir / "positive" / "cwe89").mkdir(parents=True, exist_ok=True)
(test_dir / "positive" / "cwe79").mkdir(parents=True, exist_ok=True)

print('Generating initial 2 samples...')
result1 = generate_sql_injection_sample('python', 42)
result2 = generate_xss_sample('python', 43)

# Sample 1
ext_map = {"python": "py", "javascript": "js", "typescript": "ts", "java": "java", "go": "go"}
ext = ext_map.get('python', "py")
file_name1 = f"test_resume_001.{ext}"
file_path1 = f"positive/cwe89/{file_name1}"
full_path1 = Path("dataset/test_resume") / file_path1
full_path1.parent.mkdir(parents=True, exist_ok=True)
temp_file = full_path1.with_suffix('.tmp')
temp_file.write_text(result1["code"])
temp_file.replace(full_path1)
sha256_1 = compute_sha256(result1["code"])

# Sample 2
file_name2 = f"test_resume_002.{ext}"
file_path2 = f"positive/cwe79/{file_name2}"
full_path2 = Path("dataset/test_resume") / file_path2
full_path2.parent.mkdir(parents=True, exist_ok=True)
temp_file = full_path2.with_suffix('.tmp')
temp_file.write_text(result2["code"])
temp_file.replace(full_path2)
sha256_2 = compute_sha256(result2["code"])

# Create metadata and persist
from generate_dataset_b import SampleMetadata, _load_existing_metadata, _append_metadata_atomic, _load_existing_metadata, _get_existing_hashes_and_ids, SampleMetadata, _append_metadata_atomic

csv_path = Path("dataset/test_resume/metadata.csv")
json_path = Path("dataset/test_resume/metadata.json")

metadata1 = SampleMetadata(
    sample_id="DS-B-0001",
    language='python',
    cwe=result1["cwe"],
    category="cwe89",
    label="positive",
    generator_model="qwen/qwen3.8-27b",
    generation_prompt="test",
    ground_truth=f"Test {result1['vulnerability_type']} at line {result1['vulnerable_line']}: {result1['description']}",
    file_path=f"positive/cwe89/test_resume_001.py",
    sha256=compute_sha256(result1["code"]),
    vulnerability_type=result1["vulnerability_type"],
    severity=result1["severity"],
    description=result1["description"],
    temperature=0.2,
    max_tokens=1024,
)

metadata2 = SampleMetadata(
    sample_id="DS-B-0002",
    language='python',
    cwe=result2["cwe"],
    category="cwe79",
    label="positive",
    generator_model="qwen/qwen3.8-27b",
    generation_prompt="test",
    ground_truth=f"Test {result2['vulnerability_type']} at line {result2['vulnerable_line']}: {result2['description']}",
    file_path=f"positive/cwe79/test_resume_002.py",
    sha256=compute_sha256(result2["code"]),
    vulnerability_type=result2["vulnerability_type"],
    severity=result2["severity"],
    description=result2["description"],
    temperature=0.2,
    max_tokens=1024,
)

# Persist both
_append_metadata_atomic([
    SampleMetadata(
        sample_id="DS-B-0001",
        language='python',
        cwe=result1["cwe"],
        category="cwe89",
        label="positive",
        generator_model="qwen/qwen3.8-27b",
        generation_prompt="test",
        ground_truth=f"Test {result1['vulnerability_type']} at line {result1['vulnerable_line']}: {result1['description']}",
        file_path="positive/cwe89/test_resume_001.py",
        sha256=compute_sha256(result1["code"]),
        vulnerability_type=result1["vulnerability_type"],
        severity=result1["severity"],
        description=result1["description"],
        temperature=0.2,
        max_tokens=1024,
    )
], Path("dataset/test_resume/metadata.csv"), Path("dataset/test_resume/metadata.json"))

# Save second
_append_metadata_atomic([SampleMetadata(
    sample_id="DS-B-0002",
    language='python',
    cwe=result2["cwe"],
    category="cwe79",
    label="positive",
    generator_model="qwen/qwen3.8-27b",
    generation_prompt="test",
    ground_truth=f"Test {result2['vulnerability_type']} at line {result2['vulnerable_line']}: {result2['description']}",
    file_path="positive/cwe79/test_resume_002.py",
    sha256=compute_sha256(result2["code"]),
    vulnerability_type=result2["vulnerability_type"],
    severity=result2["severity"],
    description=result2["description"],
    temperature=0.2,
    max_tokens=1024,
)], Path("dataset/test_resume/metadata.csv"), Path("dataset/test_resume/metadata.json"))

print('Initial 2 samples saved. Now testing resume...')

# Now test resume - simulate new run
print('\n--- Testing Resume ---')
from generate_dataset_b import _load_existing_metadata, _get_existing_hashes_and_ids, generate_positive_samples

# Load existing
existing = _load_existing_metadata(Path("dataset/test_resume/metadata.csv"))
print(f'Loaded {len(existing)} existing samples:')
for s in existing:
    print(f'  {s.sample_id}: {s.file_path} (hash: {s.sha256[:16]}...)')

# Test hash detection
existing_hashes, existing_ids = _get_existing_hashes_and_ids(_load_existing_metadata(Path("dataset/test_resume/metadata.csv")))
print(f'Existing hashes: {len(existing_hashes)}')

# Test that resume logic would skip duplicates
# Try to generate a duplicate
from generate_dataset_b import generate_sql_injection_sample, compute_sha256
dup_result = generate_sql_injection_sample('python', 42)
dup_hash = compute_sha256(dup_result["code"])
existing_meta = _load_existing_metadata(Path("dataset/test_resume/metadata.csv"))
existing_hashes = {m.sha256 for m in _load_existing_metadata(Path("dataset/test_resume/metadata.csv"))}
print(f'Duplicate hash check: {compute_sha256(generate_sql_injection_sample("python", 42)["code"]) in existing_hashes}')

print('\nResume test complete - existing samples recognized!')