import sys
import json
import time
import hashlib
from pathlib import Path
from collections import Counter

_REPO_ROOT = Path(r'C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode')
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / 'ai-engine'))

from evaluation.dataset_b.evaluator import load_all_samples_info
from evaluation.dataset_b.full_ace_adapter import FullACEAdapter, PipelineConfig
from evaluation.dataset_b.dataset_loader import DatasetBLoader

print("=" * 70)
print("PHASE 5.6: REAL 500-SAMPLE ABLATION STUDY")
print("=" * 70)

# Load all 500 samples
print("\nLoading 500 Dataset B samples...")
all_samples = load_all_samples_info()
pos = sum(1 for s in all_samples if s["label"] == "positive")
neg = sum(1 for s in all_samples if s["label"] == "negative")
print(f"  Loaded: {len(all_samples)} samples (Positive: {pos}, Negative: {neg})")
assert pos == 387 and neg == 113 and (pos + neg) == 500

# Create output directory
output_dir = _REPO_ROOT / "evaluation" / "results" / "research" / "ablation500"
output_dir.mkdir(parents=True, exist_ok=True)
print(f"Output directory: {output_dir}")

# Initialize DatasetBLoader
loader = DatasetBLoader(
    metadata_csv=r"C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset-b\metadata.csv",
    files_root=r"C:\Users\PRAWINKUMAR\OneDrive\Desktop\Hall-opencode\dataset\dataset\dataset-b"
)

# Define all 10 configurations
configs = {
    "A": PipelineConfig(),  # ALL ENABLED (full baseline)
    "B": PipelineConfig(hallucination_detection=False),
    "C": PipelineConfig(dependency_analysis=False),
    "D": PipelineConfig(security_analysis=False),
    "E": PipelineConfig(risk_assessment=False),
    "F": PipelineConfig(patch_generation=False),
    "G": PipelineConfig(validation=False),
    "H": PipelineConfig(legacy_ace=False),
    "I": PipelineConfig(aece=False),
    "J": PipelineConfig(multi_patch=False),
}

# Store results for each config
all_config_results = {}

# ============================================
# Run each configuration on all 500 samples
# ============================================

config_keys = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J"]

for config_key in config_keys:
    config = configs[config_key]
    print(f"\n{'='*60}")
    print(f"Configuration {config_key}: {config.to_dict()}")
    print(f"{'='*60}")
    
    start_time = time.time()
    
    # Run Full ACE on all 500 samples
    adapter = FullACEAdapter(config=config)
    ace_result = adapter.run_full_ace(all_samples)  # This may need to be adapted
    
    # ... (rest of metric computation)
    
    elapsed = time.time() - start_time
    print(f"  Completed in {elapsed/60:.1f} minutes")
    all_config_results[config_key] = {"elapsed": elapsed, "result_count": len(ace_result["results"])}

print("\n" + "=" * 70)
print("ABLATION STUDY COMPLETE")
print("=" * 70)
"