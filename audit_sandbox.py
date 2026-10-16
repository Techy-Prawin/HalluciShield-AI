#!/usr/bin/env python3
"""Trace sandbox execution for positive samples."""
import json, sys
from pathlib import Path

ROOT = Path(".")
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "ai-engine"))

with open("evaluation/results/dataset_b/sandbox/raw_results.jsonl") as f:
    lines = f.readlines()

all_records = [json.loads(l) for l in lines]

# Count execution statuses
from collections import Counter
es = Counter(d.get("execution_status", "N/A") for d in all_records)
print("Execution status distribution:", dict(es))

# COMPLETED positive samples
completed_pos = [d for d in all_records if d.get("execution_status") == "COMPLETED" and d["label"] == "positive"]
print(f"\nCOMPLETED positive samples: {len(completed_pos)}")
for d in completed_pos[:3]:
    ev = d.get("runtime_evidence") or {}
    stdout = ev.get("stdout", "")
    stderr = ev.get("stderr", "")
    rc = ev.get("returncode", "?")
    print(f"  sample={d['sample_id']} file={d['file_path']}")
    print(f"    predicted={d['predicted_label']} rc={rc}")
    print(f"    stdout={repr(stdout[:100])}")
    print(f"    stderr={repr(stderr[:200])}")
    print()

# ERROR positive samples - look at the actual error
error_pos = [d for d in all_records if d.get("execution_status") == "ERROR" and d["label"] == "positive"]
print(f"\nERROR positive samples: {len(error_pos)}")
for d in error_pos[:3]:
    ev = d.get("runtime_evidence") or {}
    stderr = ev.get("stderr", "")
    print(f"  sample={d['sample_id']} file={d['file_path']}")
    print(f"    predicted={d['predicted_label']}")
    print(f"    stderr={repr(stderr[:200])}")
    print()

print("\nSandbox Bug Analysis:")
print("  - Sandbox runs code, checks stdout/stderr for keywords: error, exception, segfault, abort, fail")
print("  - Most code in Dataset B is INCOMPLETE SNIPPETS that raise ImportError/SyntaxError")
print("  - 'error' string appears in stderr for error samples, BUT:")
print("  - The code checks: if status == 'COMPLETED' to detect vulnerability")
print("  - If status == 'ERROR', it maps to predicted_label='negative' regardless")
print("  - BUG: error/exception during code execution -> predicted_label='negative'")
print("  - This means ANY code that fails to import (most snippets) -> MISS")
print()

# Check if 'error' appears in the stderr of COMPLETED samples
completed_with_error_kw = [d for d in completed_pos if 
    any(kw in (d.get("runtime_evidence") or {}).get("stderr", "").lower() or 
        kw in (d.get("runtime_evidence") or {}).get("stdout", "").lower()
        for kw in ["error", "exception", "segfault", "abort", "fail"])]
print(f"COMPLETED positive samples with error keywords in output: {len(completed_with_error_kw)}")
print(f"  (These are the ONLY ones that could possibly be detected)")

# LLM Bug Tracing
print("\n\nLLM Loop Bug Analysis:")
print("  In run_llm_zero_shot_baseline, the for loop `for info in samples_info:` iterates 500 samples")
print("  BUT the indentation places ONLY the prompt construction inside the loop.")
print("  The API call code is DEDENTED outside the loop!")
print("  Bug: prompt is built for last sample only, then ONE API call is made")
print("  Result: 1 record in raw_results.jsonl instead of 500")
