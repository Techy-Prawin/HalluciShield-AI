import sys
from pathlib import Path
repo = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
sys.path.insert(0, str(repo))
sys.path.insert(0, str(repo / 'ai-engine'))

from evaluation.dataset_b.evaluator import load_all_samples_info
from evaluation.dataset_b.full_ace_adapter import FullACEAdapter, PipelineConfig
from evaluation.dataset_b.dataset_loader import DatasetBLoader

# Load 5 samples for smoke test
all_samples = load_all_samples_info()
samples_5 = all_samples[:5]
loader = DatasetBLoader(
    metadata_csv=r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset-b\metadata.csv',
    files_root=r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset\dataset-b'
)

print("=" * 60)
print("SMOKE TEST: FullACEAdapter with PipelineConfig")
print("=" * 60)

# Test 1: Full pipeline (ALL ENABLED - production default)
print("\n--- Test 1: Full pipeline (ALL ENABLED) ---")
adapter = FullACEAdapter(config=PipelineConfig())
for i, sample_info in enumerate(samples_5):
    fp = loader.get_file_path(sample_info)
    result = adapter.evaluate_sample(sample_info, fp)
    sid = result.get('sample_id')
    stages = result.get('stages_completed')
    vs = result.get('validation_status')
    ac = result.get('ace_score')
    print(f"  {sid}: stages={stages}, validation_status={vs}, ace_score={ac}")

# Test 2: Hallucination OFF
print("\n--- Test 2: Hallucination OFF ---")
config_no_hall = PipelineConfig(hallucination_detection=False)
adapter2 = FullACEAdapter(config=config_no_hall)
for i, sample_info in enumerate(samples_5):
    fp = loader.get_file_path(sample_info)
    result = adapter2.evaluate_sample(sample_info, fp)
    sid = result.get('sample_id')
    stages = result.get('stages_completed')
    # Check if hallucination stage is in stages_completed
    has_hall = 'hallucination' in stages
    # Check stage_records for hallucination
    sr = result.get('stage_records', {})
    hall_sr = sr.get('hallucination', {})
    hall_status = hall_sr.get('status') if isinstance(hall_sr, dict) else 'N/A'
    print(f"  {sid}: stages={stages}, hallucination_status={hall_status}, has_hall_in_stages={has_hall}")

# Test 3: Dependency OFF
print("\n--- Test 3: Dependency OFF ---")
config_no_dep = PipelineConfig(dependency_analysis=False)
adapter3 = FullACEAdapter(config=config_no_dep)
for i, sample_info in enumerate(samples_5):
    fp = loader.get_file_path(sample_info)
    result = adapter3.evaluate_sample(sample_info, fp)
    sid = result.get('sample_id')
    stages = result.get('stages_completed')
    sr = result.get('stage_records', {})
    dep_sr = sr.get('dependency', {})
    dep_status = dep_sr.get('status') if isinstance(dep_sr, dict) else 'N/A'
    print(f"  {sid}: stages={stages}, dependency_status={dep_status}")

# Test 4: Patch OFF
print("\n--- Test 4: Patch OFF ---")
config_no_patch = PipelineConfig(patch_generation=False)
adapter4 = FullACEAdapter(config=config_no_patch)
for i, sample_info in enumerate(samples_5):
    fp = loader.get_file_path(sample_info)
    result = adapter4.evaluate_sample(sample_info, fp)
    sid = result.get('sample_id')
    stages = result.get('stages_completed')
    sr = result.get('stage_records', {})
    patch_sr = sr.get('patch', {})
    patch_status = patch_sr.get('status') if isinstance(patch_sr, dict) else 'N/A'
    print(f"  {sid}: stages={stages}, patch_status={patch_status}")

# Test 5: Validation OFF
print("\n--- Test 5: Validation OFF ---")
config_no_val = PipelineConfig(validation=False)
adapter5 = FullACEAdapter(config=config_no_val)
for i, sample_info in enumerate(samples_5):
    fp = loader.get_file_path(sample_info)
    result = adapter5.evaluate_sample(sample_info, fp)
    sid = result.get('sample_id')
    stages = result.get('stages_completed')
    sr = result.get('stage_records', {})
    val_sr = sr.get('validation', {})
    val_status = val_sr.get('status') if isinstance(val_sr, dict) else 'N/A'
    print(f"  {sid}: stages={stages}, validation_status={val_status}")

# Test 6: Legacy ACE + AECE OFF
print("\n--- Test 6: Legacy ACE / AECE OFF ---")
config_no_ace = PipelineConfig(legacy_ace=False, aece=False)
adapter6 = FullACEAdapter(config=config_no_ace)
for i, sample_info in enumerate(samples_5):
    fp = loader.get_file_path(sample_info)
    result = adapter6.evaluate_sample(sample_info, fp)
    sid = result.get('sample_id')
    stages = result.get('stages_completed')
    sr = result.get('stage_records', {})
    conf_sr = sr.get('confidence', {})
    conf_status = conf_sr.get('status') if isinstance(conf_sr, dict) else 'N/A'
    ace_score = result.get('ace_score')
    print(f"  {sid}: stages={stages}, confidence_status={conf_status}, ace_score={ace_score}")

print("\n" + "=" * 60)
print("SMOKE TEST COMPLETE")
print("=" * 60)