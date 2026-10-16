"""Phase 3.3 — 5-Sample Production Pipeline Trace Runner.

Runs the 5 specified samples:
- 3 positive: CWE-89, CWE-79, CWE-798
- 2 negative: clean (Python, TypeScript)

Records complete stage-by-stage execution trace:
sample -> hallucination -> dependency -> security -> risk -> patch -> validation -> confidence -> final
"""

import json
import sys
from pathlib import Path
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(REPO_ROOT / ".env")
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
AI_ENGINE = REPO_ROOT / "ai-engine"
if str(AI_ENGINE) not in sys.path:
    sys.path.insert(0, str(AI_ENGINE))

from evaluation.dataset_b.full_ace_adapter import FullACEAdapter
from evaluation.dataset_b.evaluator import get_dataset_loader, load_all_samples_info

loader = get_dataset_loader()
all_samples = load_all_samples_info()

# Select the exact 5 samples
target_files = [
    "positive/cwe89/cwe89_001.py",
    "positive/cwe79/cwe79_001.js",
    "positive/cwe798/cwe798_001.js",
    "negative/clean/clean_001.py",
    "negative/clean/clean_002.ts",
]

selected_samples = []
for tf in target_files:
    matched = next((s for s in all_samples if s["file_path"] == tf), None)
    if matched:
        selected_samples.append(matched)
    else:
        raise ValueError(f"Could not find sample for file: {tf}")

adapter = FullACEAdapter()
results = []

print("=" * 70)
print("Phase 3.3 — 5-Sample Full ACE Production Trace")
print("=" * 70)

for s in selected_samples:
    fp = loader.get_file_path(s)
    record = adapter.evaluate_sample(s, fp)
    results.append(record)
    print(f"\n[Sample] {s['sample_id']} | File: {s['file_path']} | Category: {s['category']} | Label: {s['label']}")
    print(f"  Stages completed : {record['stages_completed']}")
    print(f"  Predicted Label  : {record['predicted_label']} (Correct: {record['detection_correct']})")
    print(f"  ACE Confidence   : {record['ace_score']}")
    print(f"  Overall Risk     : {record['overall_risk_score']} ({record['overall_risk_level']})")
    print(f"  Validation Status: {record['validation_status']}")

out_dir = REPO_ROOT / "evaluation" / "results" / "dataset_b" / "dry_run"
out_dir.mkdir(parents=True, exist_ok=True)
out_file = out_dir / "production_trace_5_samples.json"
with open(out_file, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

print(f"\nSaved full trace to: {out_file}")
