#!/usr/bin/env python3
"""
Adaptive Learning Experiment Framework for HalluciShield AI.

Runs controlled historical-learning stages:
- Stage 0: 0 validated patches (cold start)
- Stage 1: 50 validated patches
- Stage 2: 100 validated patches
- Stage 3: 250 validated patches

Measures:
- Patch ranking success (rate at which optimal patch is ranked #1)
- Confidence calibration (Brier Score, ECE)
- Validation success rate
- False acceptance rate (accepted patches that fail ground-truth validation)
- False rejection rate (rejected patches that would succeed)

RESEARCH INTEGRITY:
- Strict split between training/history data and evaluation test data
- Zero data leakage into evaluation samples
- Fixed seed (42) for deterministic reproducibility
- Outputs to `evaluation/results/research/adaptive_learning/`
"""

import json
import os
import sys
import random
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
AI_ENGINE = REPO_ROOT / "ai-engine"
if str(AI_ENGINE) not in sys.path:
    sys.path.insert(0, str(AI_ENGINE))

from app.agents.adaptive_learning import AdaptiveLearningEngine
from app.agents.calibration import CalibrationEngine
from app.agents.models import (
    RecordLearningRequest,
    ApprovalDecision,
    DeploymentOutcome,
    PatchValidationResult,
    CompilationScore,
    UnitTestScore,
    RegressionScore,
    SecurityValidationScore,
    FunctionalBehaviorScore,
    PerformanceImpactScore,
    ValidationStatus,
)

OUTPUT_DIR = REPO_ROOT / "evaluation" / "results" / "research" / "adaptive_learning"
STAGES = [0, 50, 100, 250]


def generate_synthetic_history_dataset(total_count: int = 250, seed: int = 42) -> List[RecordLearningRequest]:
    """Generate deterministic training records for history stages."""
    rng = random.Random(seed)
    vuln_types = ["SQL_INJECTION", "CROSS_SITE_SCRIPTING", "COMMAND_INJECTION", "PATH_TRAVERSAL"]
    strategies = ["parameterized_query", "input_validation", "output_encoding", "allowlist"]

    # Defined ground truth strategy effectiveness
    # e.g., parameterized_query is highly effective for SQL_INJECTION
    effectiveness_map = {
        ("SQL_INJECTION", "parameterized_query"): 0.95,
        ("SQL_INJECTION", "input_validation"): 0.50,
        ("CROSS_SITE_SCRIPTING", "output_encoding"): 0.90,
        ("CROSS_SITE_SCRIPTING", "allowlist"): 0.60,
        ("COMMAND_INJECTION", "parameterized_query"): 0.92,
        ("PATH_TRAVERSAL", "allowlist"): 0.88,
    }

    records = []
    for i in range(total_count):
        vt = vuln_types[i % len(vuln_types)]
        strat = strategies[(i * 3) % len(strategies)]
        prob_success = effectiveness_map.get((vt, strat), 0.40)

        is_success = rng.random() < prob_success
        decision = ApprovalDecision.APPROVED if is_success else ApprovalDecision.REJECTED
        outcome = DeploymentOutcome.SUCCESS if is_success else DeploymentOutcome.ROLLBACK
        conf = rng.uniform(70.0, 95.0) if is_success else rng.uniform(30.0, 65.0)

        req = RecordLearningRequest(
            vulnerability_id=f"hist-vuln-{i:04d}",
            patch_id=f"hist-patch-{i:04d}",
            vulnerability_type=vt,
            patch_strategy=strat,
            validation_features={"compilation": 1.0 if is_success else 0.0},
            confidence_score=conf,
            developer_decision=decision,
            developer_id="developer_auto_sim",
            deployment_outcome=outcome,
        )
        records.append(req)

    return records


def generate_evaluation_test_set(count: int = 50, seed: int = 999) -> List[Dict[str, Any]]:
    """Generate isolated evaluation test samples."""
    rng = random.Random(seed)
    vuln_types = ["SQL_INJECTION", "CROSS_SITE_SCRIPTING", "COMMAND_INJECTION", "PATH_TRAVERSAL"]
    test_cases = []

    for i in range(count):
        vt = vuln_types[i % len(vuln_types)]
        # Candidates for this vulnerability
        candidates = [
            {"patch_id": f"eval-{i}-p1", "strategy": "parameterized_query" if "SQL" in vt or "COMMAND" in vt else "output_encoding"},
            {"patch_id": f"eval-{i}-p2", "strategy": "input_validation"},
            {"patch_id": f"eval-{i}-p3", "strategy": "allowlist"},
        ]
        # Ground truth validity
        for c in candidates:
            strat = c["strategy"]
            if ("SQL" in vt and strat == "parameterized_query") or \
               ("XSS" in vt and strat == "output_encoding") or \
               ("COMMAND" in vt and strat == "parameterized_query") or \
               ("TRAVERSAL" in vt and strat == "allowlist"):
                c["ground_truth_valid"] = True
            else:
                c["ground_truth_valid"] = (rng.random() < 0.25)

        test_cases.append({
            "eval_id": f"eval-{i:03d}",
            "vulnerability_type": vt,
            "candidates": candidates,
        })

    return test_cases


def run_adaptive_learning_experiment(seed: int = 42) -> Dict[str, Any]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    all_history = generate_synthetic_history_dataset(total_count=250, seed=seed)
    eval_set = generate_evaluation_test_set(count=50, seed=seed + 100)

    calibration_engine = CalibrationEngine()
    stage_results = {}
    raw_records = []

    for stage_count in STAGES:
        # Train engine on history subset
        engine = AdaptiveLearningEngine()
        training_records = all_history[:stage_count]
        for tr in training_records:
            engine.record_learning_event(tr)

        # Extract learned patterns
        patterns = engine.extract_patterns()

        # Evaluate on isolated test set
        ranking_successes = 0
        total_eval = len(eval_set)
        validation_successes = 0
        false_acceptances = 0
        false_rejections = 0

        calib_samples = []

        for case in eval_set:
            vt = case["vulnerability_type"]
            cands = case["candidates"]

            # Rank candidates using learned historical weights
            ranked_cands = []
            for c in cands:
                hw = engine.get_historical_weight(vt, c["strategy"])
                # Base confidence score adjusted by historical weight
                base_score = 70.0
                adjusted_score = base_score * 0.7 + (hw * 100.0) * 0.3
                ranked_cands.append((c, adjusted_score))

            # Sort descending by score
            ranked_cands.sort(key=lambda x: x[1], reverse=True)
            top_cand, top_score = ranked_cands[0]

            is_top_valid = top_cand["ground_truth_valid"]
            if is_top_valid:
                ranking_successes += 1
                validation_successes += 1

            # Auto-approval decision if score >= 75
            is_accepted = (top_score >= 75.0)
            if is_accepted and not is_top_valid:
                false_acceptances += 1
            if not is_accepted and is_top_valid:
                false_rejections += 1

            calib_samples.append({
                "predicted_confidence": top_score / 100.0,
                "actual_outcome": 1 if is_top_valid else 0,
                "sample_id": f"stage-{stage_count}-{case['eval_id']}",
            })

            raw_records.append({
                "stage": stage_count,
                "eval_id": case["eval_id"],
                "vulnerability_type": vt,
                "top_strategy": top_cand["strategy"],
                "top_score": round(top_score, 2),
                "is_valid": is_top_valid,
                "accepted": is_accepted,
            })

        # Calculate calibration metrics
        calib_metrics = calibration_engine.calculate_calibration(calib_samples)

        stage_results[f"stage_{stage_count}"] = {
            "training_samples": stage_count,
            "patterns_learned": len(patterns),
            "ranking_success_rate": round(ranking_successes / total_eval, 4),
            "validation_success_rate": round(validation_successes / total_eval, 4),
            "false_acceptance_rate": round(false_acceptances / total_eval, 4),
            "false_rejection_rate": round(false_rejections / total_eval, 4),
            "brier_score": calib_metrics.get("brier_score", 0.0),
            "ece": calib_metrics.get("expected_calibration_error", 0.0),
        }

    # Save outputs
    with open(OUTPUT_DIR / "raw_results.jsonl", "w", encoding="utf-8") as f:
        for r in raw_records:
            f.write(json.dumps(r) + "\n")

    with open(OUTPUT_DIR / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(stage_results, f, indent=2)

    with open(OUTPUT_DIR / "config.json", "w", encoding="utf-8") as f:
        json.dump({
            "experiment_id": "exp-adaptive-learning-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stages": STAGES,
            "evaluation_test_samples": len(eval_set),
            "seed": seed,
            "leakage_protection": "Disjoint training and evaluation partitions",
        }, f, indent=2)

    # Markdown report
    md = f"""# Adaptive Learning Experiment

Controlled evaluation across historical feedback stages: 0, 50, 100, and 250 validated patches.

| Training Stage | Validated Patches | Patterns | Ranking Success | Validation Success | False Acceptance | False Rejection | Brier Score | ECE |
|---|---|---|---|---|---|---|---|---|
"""
    for k, s in stage_results.items():
        md += f"| {k} | {s['training_samples']} | {s['patterns_learned']} | {s['ranking_success_rate']:.4f} | {s['validation_success_rate']:.4f} | {s['false_acceptance_rate']:.4f} | {s['false_rejection_rate']:.4f} | {s['brier_score']:.4f} | {s['ece']:.4f} |\n"

    md += "\n*Strictly isolates training data from evaluation data.*\n"
    with open(OUTPUT_DIR / "README.md", "w", encoding="utf-8") as f:
        f.write(md)

    return stage_results


if __name__ == "__main__":
    res = run_adaptive_learning_experiment()
    print(json.dumps(res, indent=2))
