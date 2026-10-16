#!/usr/bin/env python3
"""
Cross-Language Research Evaluation Framework for HalluciShield AI.

Evaluates performance independently across:
- Java
- Python
- JavaScript
- TypeScript
- Go

Calculates for each language:
- TP, FP, TN, FN
- Precision, Recall, F1, Accuracy
- FPR, FNR
- Latency (mean, p50, p95)

RESEARCH INTEGRITY:
- Does NOT alter existing Dataset B results.
- Outputs exclusively to `evaluation/results/research/cross_language/`.
- Reproducible from stored raw evidence.
"""

import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any

# Setup repo root path
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
AI_ENGINE = REPO_ROOT / "ai-engine"
if str(AI_ENGINE) not in sys.path:
    sys.path.insert(0, str(AI_ENGINE))

from evaluation.dataset_b.dataset_loader import DatasetBLoader

OUTPUT_DIR = REPO_ROOT / "evaluation" / "results" / "research" / "cross_language"
LANGUAGES = ["java", "python", "javascript", "typescript", "go"]


def calculate_binary_metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, float]:
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
    }


def run_cross_language_evaluation(
    max_samples_per_lang: int = 20,
    seed: int = 42,
) -> Dict[str, Any]:
    """
    Run independent cross-language evaluation on Dataset B samples.
    """
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    loader = DatasetBLoader()
    
    # Try importing real production scanner or analyze functions
    from app.analyzer.security_scanner import SecurityScanner
    scanner = SecurityScanner()

    lang_results: Dict[str, Any] = {}
    raw_records = []
    
    for lang in LANGUAGES:
        samples = loader.get_samples(language=lang)
        if max_samples_per_lang:
            samples = samples[:max_samples_per_lang]

        tp = fp = tn = fn = 0
        latencies_ms = []

        for s in samples:
            code = loader.read_code(s)
            ground_truth_vuln = (s.get("label", "").lower() == "positive")
            
            t0 = time.time()
            # Run production AST/regex/semgrep security scan
            scan_res = scanner.scan_code(code, language=lang)
            dur_ms = int((time.time() - t0) * 1000)
            latencies_ms.append(dur_ms)

            detected = len(scan_res.findings) > 0

            if detected and ground_truth_vuln:
                tp += 1
                pred_label = "TP"
            elif detected and not ground_truth_vuln:
                fp += 1
                pred_label = "FP"
            elif not detected and not ground_truth_vuln:
                tn += 1
                pred_label = "TN"
            else:
                fn += 1
                pred_label = "FN"

            raw_records.append({
                "sample_id": s["sample_id"],
                "language": lang,
                "ground_truth": "positive" if ground_truth_vuln else "negative",
                "predicted_detected": detected,
                "finding_count": len(scan_res.findings),
                "outcome": pred_label,
                "latency_ms": dur_ms,
            })

        metrics = calculate_binary_metrics(tp, fp, tn, fn)
        latencies_ms.sort()
        mean_lat = sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0
        p50_lat = latencies_ms[len(latencies_ms) // 2] if latencies_ms else 0.0
        p95_lat = latencies_ms[int(len(latencies_ms) * 0.95)] if latencies_ms else 0.0

        lang_results[lang] = {
            "total_samples": len(samples),
            "confusion_matrix": {
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
            },
            "metrics": metrics,
            "latency": {
                "mean_ms": round(mean_lat, 2),
                "p50_ms": p50_lat,
                "p95_ms": p95_lat,
            },
        }

    # Save raw results
    raw_path = OUTPUT_DIR / "raw_results.jsonl"
    with open(raw_path, "w", encoding="utf-8") as f:
        for r in raw_records:
            f.write(json.dumps(r) + "\n")

    # Save metrics
    metrics_path = OUTPUT_DIR / "metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(lang_results, f, indent=2)

    # Save config & reproducibility metadata
    config_path = OUTPUT_DIR / "config.json"
    config_data = {
        "experiment_id": "exp-cross-language-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset_version": "Dataset B v1.0",
        "languages": LANGUAGES,
        "samples_per_language": {lang: lang_results[lang]["total_samples"] for lang in LANGUAGES},
        "seed": seed,
        "environment": {
            "python_version": sys.version.split()[0],
            "os": sys.platform,
        },
    }
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2)

    # Save README
    readme_path = OUTPUT_DIR / "README.md"
    readme_content = f"""# Cross-Language Research Evaluation

Evaluates security detection performance independently across 5 languages on Dataset B.

## Summary Table

| Language | Samples | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy | FPR | FNR | Mean Latency (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
"""
    for lang in LANGUAGES:
        res = lang_results[lang]
        cm = res["confusion_matrix"]
        m = res["metrics"]
        lat = res["latency"]
        readme_content += f"| {lang.capitalize()} | {res['total_samples']} | {cm['tp']} | {cm['fp']} | {cm['tn']} | {cm['fn']} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | {m['accuracy']:.4f} | {m['fpr']:.4f} | {m['fnr']:.4f} | {lat['mean_ms']} |\n"

    readme_content += "\n*Generated deterministically from raw_results.jsonl*\n"
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(readme_content)

    return lang_results


if __name__ == "__main__":
    res = run_cross_language_evaluation(max_samples_per_lang=10)
    print(json.dumps(res, indent=2))
