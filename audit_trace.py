#!/usr/bin/env python3
"""Audit trace script for Dataset B Phase 3 evaluation."""
import json, sys, os
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "ai-engine"))

# ── 1. LLM results: count lines ──────────────────────────────────────────────
llm_path = ROOT / "evaluation/results/dataset_b/llm_zero_shot/raw_results.jsonl"
with open(llm_path) as f:
    llm_lines = f.readlines()
print(f"[LLM] Total records in raw_results.jsonl: {len(llm_lines)}")
for line in llm_lines:
    d = json.loads(line)
    print(f"  sample_id={d['sample_id']} label={d['label']} predicted={d['predicted_label']} scanner={d['scanner_result']}")

# ── 2. Semgrep results ────────────────────────────────────────────────────────
semgrep_path = ROOT / "evaluation/results/dataset_b/semgrep/raw_results.jsonl"
with open(semgrep_path) as f:
    sem_lines = f.readlines()
print(f"\n[Semgrep] Total records: {len(sem_lines)}")
sc = Counter(json.loads(l)['scanner_result'] for l in sem_lines)
print(f"  scanner_result distribution: {dict(sc)}")
pred = Counter(json.loads(l)['predicted_label'] for l in sem_lines)
print(f"  predicted_label distribution: {dict(pred)}")
fn = sum(1 for l in sem_lines if json.loads(l)['false_negative'])
print(f"  False Negatives (positive label but predicted negative): {fn}")
tp = sum(1 for l in sem_lines if json.loads(l)['detection_correct'] and json.loads(l)['predicted_label'] == 'positive')
print(f"  True Positives: {tp}")

# Trace CWE-specific positive samples
by_cwe = {}
for line in sem_lines:
    d = json.loads(line)
    cwe = d.get('cwe', 'NONE')
    if d['label'] == 'positive' and cwe not in by_cwe:
        by_cwe[cwe] = d

print("\n[Semgrep] CWE sample traces (positive label only):")
for target_cwe in ['CWE-89', 'CWE-79', 'CWE-78', 'CWE-798']:
    d = by_cwe.get(target_cwe)
    if d:
        sid = d['sample_id']
        pred_lbl = d['predicted_label']
        scanner = d['scanner_result']
        fc = d['finding_count']
        fp = d['file_path']
        print(f"  {target_cwe}: sample={sid} predicted={pred_lbl} scanner={scanner} findings={fc} file={fp}")
    else:
        print(f"  {target_cwe}: NOT FOUND in results")

# ── 3. Full ACE results ───────────────────────────────────────────────────────
ace_path = ROOT / "evaluation/results/dataset_b/full_ace/raw_results.jsonl"
with open(ace_path) as f:
    ace_lines = f.readlines()
print(f"\n[Full ACE] Total records: {len(ace_lines)}")
sc = Counter(json.loads(l)['scanner_result'] for l in ace_lines)
print(f"  scanner_result distribution: {dict(sc)}")
err_msgs = Counter(json.loads(l).get('error_message','') for l in ace_lines)
print(f"  Error messages: {dict(err_msgs)}")

# ── 4. Sandbox results ────────────────────────────────────────────────────────
sandbox_path = ROOT / "evaluation/results/dataset_b/sandbox/raw_results.jsonl"
with open(sandbox_path) as f:
    sandbox_lines = f.readlines()
print(f"\n[Sandbox] Total records: {len(sandbox_lines)}")
sc = Counter(json.loads(l)['scanner_result'] for l in sandbox_lines)
print(f"  scanner_result distribution: {dict(sc)}")
es = Counter(json.loads(l).get('execution_status','') for l in sandbox_lines)
print(f"  execution_status distribution: {dict(es)}")
detected_count = sum(1 for l in sandbox_lines if json.loads(l).get('predicted_label') == 'positive')
print(f"  Detected as positive: {detected_count}")

# ── 5. Verify positive/negative counts ───────────────────────────────────────
pos_count = sum(1 for l in sem_lines if json.loads(l)['label'] == 'positive')
neg_count = sum(1 for l in sem_lines if json.loads(l)['label'] == 'negative')
print(f"\n[Dataset] positive={pos_count} negative={neg_count} total={pos_count+neg_count}")

# ── 6. Trace 5 positive samples through Full ACE ─────────────────────────────
print("\n[Full ACE] 5 positive sample traces:")
positives_ace = [json.loads(l) for l in ace_lines if json.loads(l)['label'] == 'positive'][:5]
for d in positives_ace:
    sid = d['sample_id']
    cwe = d.get('cwe')
    pred = d['predicted_label']
    scanner = d['scanner_result']
    stages = d.get('stages_completed', [])
    err = d.get('error_message')
    fp = d['file_path']
    print(f"  sample={sid} cwe={cwe} predicted={pred} scanner={scanner} stages={stages} err={err!r} file={fp}")

# ── 7. Check the semgrep scan target path bug ─────────────────────────────────
print("\n[Semgrep] Checking what path is passed to SecurityAnalysisAgent.analyze_security():")
# Load one sample and check what fp is
from evaluation.dataset_b.dataset_loader import DatasetBLoader
METADATA_CSV = ROOT / "dataset" / "dataset-b" / "metadata.csv"
DATASET_FILES_ROOT = ROOT / "dataset" / "dataset" / "dataset-b"
loader = DatasetBLoader(metadata_csv=METADATA_CSV, files_root=DATASET_FILES_ROOT)
samples = loader.get_samples()[:3]
for s in samples:
    fp = loader.get_file_path(s)
    exists = fp.exists()
    size = fp.stat().st_size if exists else 0
    print(f"  sample={s['sample_id']} fp={fp} exists={exists} size={size}")

print("\n[Semgrep] When SecurityAnalysisAgent is called with a SINGLE FILE path,")
print("  the fallback scanner's os.walk() will only walk that file's PARENT DIRECTORY.")
print("  This could cause it to scan extra files or the entire directory.")
print("  Let's verify by checking what os.walk does with a single file:")
print("  -> run_scan(target_path=str(fp)) where fp is a single .py file")
print("  -> fallback scanner does: os.walk(target_path)")
print("  -> If target_path is a FILE, os.walk will yield NOTHING (it only walks directories)")
print("  -> BUG: os.walk on a FILE yields no results -> 0 findings -> all negatives")
