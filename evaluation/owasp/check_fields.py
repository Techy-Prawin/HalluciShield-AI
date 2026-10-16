"""Inspect raw_results.jsonl field structure."""
import json
from pathlib import Path

raw = Path("evaluation/results/owasp/raw_results.jsonl")
with open(raw, "r", encoding="utf-8") as f:
    first = json.loads(f.readline())

print("Keys in first record:")
for k in sorted(first.keys()):
    v = first[k]
    if isinstance(v, dict):
        print(f"  {k}: dict({list(v.keys())[:3]}...)")
    elif isinstance(v, list):
        print(f"  {k}: list[{len(v)}]")
    else:
        print(f"  {k}: {repr(v)}")
