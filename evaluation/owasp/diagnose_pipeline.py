"""Diagnose why all OWASP samples produce predicted_label=negative."""
import json
from pathlib import Path
from collections import Counter

RAW = Path("evaluation/results/owasp/raw_results.jsonl")

findings_counts = Counter()
hallucination_findings = Counter()
dep_findings = Counter()
sec_findings = Counter()
stages_set = Counter()
risk_levels = Counter()

with open(RAW, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        findings_counts[rec.get("all_findings_count", 0)] += 1
        stages_set[str(rec.get("stages_completed", []))] += 1
        risk_levels[rec.get("overall_risk_level", "?")] += 1
        sr = rec.get("stage_records", {})
        hallucination_findings[sr.get("hallucination", {}).get("finding_count", 0)] += 1
        dep_findings[sr.get("dependency", {}).get("finding_count", 0)] += 1
        sec_findings[sr.get("security", {}).get("finding_count", 0)] += 1

print("all_findings_count distribution:")
for k in sorted(findings_counts):
    print(f"  {k}: {findings_counts[k]}")

print("\nhallucination finding_count distribution:")
for k in sorted(hallucination_findings):
    print(f"  {k}: {hallucination_findings[k]}")

print("\ndependency finding_count distribution:")
for k in sorted(dep_findings):
    print(f"  {k}: {dep_findings[k]}")

print("\nsecurity finding_count distribution:")
for k in sorted(sec_findings):
    print(f"  {k}: {sec_findings[k]}")

print("\noveral_risk_level distribution:")
for k, v in risk_levels.most_common():
    print(f"  {k}: {v}")

# Sample a positive oracle record to see stage details
with open(RAW, "r", encoding="utf-8") as f:
    for line in f:
        rec = json.loads(line)
        if rec.get("label") == "positive":
            print("\nSample positive record stage_records (security stage):")
            sec = rec.get("stage_records", {}).get("security", {})
            print(json.dumps(sec, indent=2))
            break
