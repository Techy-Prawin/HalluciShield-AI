"""
HalluciShield Experimental Evaluation Script
============================================
Runs real experiments against the 9-category benchmark dataset,
computes detection metrics (precision, recall, F1, accuracy),
measures latency, and produces IEEE-ready tables.

Usage:
    cd ai-engine
    python -m evaluation.run_evaluation
"""

import json
import os
import sys
import time
import statistics
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ai-engine"))

from app.agents.models import (
    ExperimentDataSource,
    ExperimentMode,
    RunExperimentRequest,
    VulnerabilityTestCategory,
)
from app.agents.experiment_runner import experiment_runner
from app.agents.test_dataset import (
    ALL_TEST_CASES,
    ALL_TEST_CASES_BY_CATEGORY,
    DATASET_VERSION,
)
from app.agents.real_benchmark_dataset import (
    REAL_BENCHMARK_CASES,
    REAL_BENCHMARK_BY_ID,
    REAL_BENCHMARK_VERSION,
)

EVAL_DIR = Path(__file__).parent
RAW_DIR = EVAL_DIR / "raw_results"
PROCESSED_DIR = EVAL_DIR / "processed_results"
CM_DIR = EVAL_DIR / "confusion_matrices"
LATENCY_DIR = EVAL_DIR / "latency"
ABLATION_DIR = EVAL_DIR / "ablation"

CATEGORIES = [cat.value for cat in VulnerabilityTestCategory]


def run_simulation_experiment():
    """Run simulation experiment across all modes."""
    print("\n[1/4] Running simulation experiment (all modes, 45 test cases)...")
    req = RunExperimentRequest(
        experiment_name="eval-simulation-full",
        data_source=ExperimentDataSource.SIMULATION,
        modes=list(ExperimentMode),
    )
    start = time.time()
    run = experiment_runner.run_experiment(req)
    elapsed = time.time() - start
    print(f"  Completed in {elapsed:.2f}s, {len(run.records)} records")
    return run


def run_real_experiment():
    """Run real experiment on the 9-case real benchmark."""
    print("\n[2/4] Running real experiment (9 real benchmark cases)...")
    req = RunExperimentRequest(
        experiment_name="eval-real-full",
        data_source=ExperimentDataSource.REAL,
        modes=[ExperimentMode.HALLUCISHIELD],
    )
    start = time.time()
    run = experiment_runner.run_experiment(req)
    elapsed = time.time() - start
    print(f"  Completed in {elapsed:.2f}s, {len(run.records)} records")
    return run


def run_real_experiment_all_modes():
    """Run real experiment on the 9-case real benchmark with all modes."""
    print("\n[3/4] Running real experiment (all modes, 9 real benchmark cases)...")
    req = RunExperimentRequest(
        experiment_name="eval-real-all-modes",
        data_source=ExperimentDataSource.REAL,
        modes=list(ExperimentMode),
    )
    start = time.time()
    run = experiment_runner.run_experiment(req)
    elapsed = time.time() - start
    print(f"  Completed in {elapsed:.2f}s, {len(run.records)} records")
    return run


def compute_confusion_matrix(records, mode, category=None):
    """Compute TP, FP, FN, TN from records for a given mode and optional category."""
    mode_records = [r for r in records if r.mode == mode]
    if category:
        mode_records = [r for r in mode_records if r.vuln_category.value == category]

    tp = sum(1 for r in mode_records if r.detection_correct and r.detection_result)
    fp = sum(1 for r in mode_records if r.false_positive)
    fn = sum(1 for r in mode_records if r.false_negative)
    tn = sum(1 for r in mode_records if r.detection_correct and not r.detection_result)

    total = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "total": total,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "fpr": round(fpr, 4),
    }


def produce_simulation_table(run):
    """Produce Table I: Simulation Experiment Results (all modes)."""
    print("\n[4/4] Producing IEEE-ready tables...\n")
    
    table = {}
    for mode_str, metrics in run.metrics_by_mode.items():
        table[mode_str] = {
            "total_tests": metrics.total_tests,
            "tp": metrics.true_positives,
            "fp": metrics.false_positives,
            "fn": metrics.false_negatives,
            "tn": metrics.true_negatives,
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1": metrics.f1,
            "accuracy": metrics.detection_accuracy,
            "fpr": metrics.false_positive_rate,
            "patch_success_rate": metrics.patch_success_rate,
            "regression_rate": metrics.regression_rate,
            "avg_validation_time_ms": metrics.avg_validation_time_ms,
            "confidence_calibration": metrics.confidence_calibration,
            "total_patches_generated": metrics.total_patches_generated,
            "total_patches_validated": metrics.total_patches_validated,
        }
    return table


def produce_real_table(run):
    """Produce Table II: Real Experiment Results (HALLUCISHIELD mode only)."""
    records = [r for r in run.records if r.mode == ExperimentMode.HALLUCISHIELD]
    
    per_category = {}
    for cat in CATEGORIES:
        cat_records = [r for r in records if r.vuln_category.value == cat]
        if not cat_records:
            continue
        
        tp = sum(1 for r in cat_records if r.detection_correct and r.detection_result)
        fp = sum(1 for r in cat_records if r.false_positive)
        fn = sum(1 for r in cat_records if r.false_negative)
        tn = sum(1 for r in cat_records if r.detection_correct and not r.detection_result)
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        
        confidences = [r.best_confidence_score for r in cat_records if r.best_confidence_score > 0]
        avg_conf = statistics.mean(confidences) if confidences else 0.0
        avg_time = statistics.mean([r.execution_time_ms for r in cat_records])
        
        per_category[cat] = {
            "test_count": len(cat_records),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "avg_confidence": round(avg_conf, 4),
            "avg_latency_ms": round(avg_time, 1),
            "detections": [r.actual_scanner_result for r in cat_records],
        }
    
    # Overall
    overall = compute_confusion_matrix(run.records, ExperimentMode.HALLUCISHIELD)
    all_confidences = [r.best_confidence_score for r in records if r.best_confidence_score > 0]
    overall["avg_confidence"] = round(statistics.mean(all_confidences), 4) if all_confidences else 0.0
    overall["avg_latency_ms"] = round(statistics.mean([r.execution_time_ms for r in records]), 1)
    
    return {"per_category": per_category, "overall": overall}


def produce_per_category_simulation_table(run):
    """Produce Table III: Per-Category Detection Metrics (simulation, HALLUCISHIELD mode)."""
    hallu_records = [r for r in run.records if r.mode == ExperimentMode.HALLUCISHIELD]
    
    per_cat = {}
    for cat in CATEGORIES:
        cm = compute_confusion_matrix(hallu_records, ExperimentMode.HALLUCISHIELD, category=cat)
        per_cat[cat] = cm
    return per_cat


def produce_real_per_mode_table(run):
    """Produce Table IV: Real Experiment — Per-Mode Comparison."""
    modes = set(r.mode for r in run.records)
    per_mode = {}
    for mode in modes:
        mode_records = [r for r in run.records if r.mode == mode]
        if not mode_records:
            continue
        
        tp = sum(1 for r in mode_records if r.detection_correct and r.detection_result)
        fp = sum(1 for r in mode_records if r.false_positive)
        fn = sum(1 for r in mode_records if r.false_negative)
        tn = sum(1 for r in mode_records if r.detection_correct and not r.detection_result)
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) > 0 else 0.0
        
        confidences = [r.best_confidence_score for r in mode_records if r.best_confidence_score > 0]
        avg_conf = statistics.mean(confidences) if confidences else 0.0
        avg_time = statistics.mean([r.execution_time_ms for r in mode_records])
        
        per_mode[mode.value] = {
            "test_count": len(mode_records),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "accuracy": round(accuracy, 4),
            "avg_confidence": round(avg_conf, 4),
            "avg_latency_ms": round(avg_time, 1),
        }
    return per_mode


def run_latency_benchmark():
    """Measure per-agent and end-to-end latency."""
    print("\n[LATENCY] Measuring per-agent latency...")
    results = {}
    
    # Import agents
    from app.agents.security_agent import SecurityAnalysisAgent
    from app.agents.hallucination_agent import HallucinationDetectionAgent
    from app.agents.dependency_agent import DependencyAnalysisAgent
    from app.agents.patch_agent import PatchGenerationAgent
    from app.agents.confidence_engine import ConfidenceEngine
    from app.agents.risk_engine import RiskEngine
    from app.agents.models import PatchValidationResult, PatchCandidate, ValidateCandidatesRequest
    
    import tempfile
    import os
    
    # Create a sample workspace
    tmp_dir = tempfile.mkdtemp(prefix="hs_latency_")
    with open(os.path.join(tmp_dir, "test.py"), "w") as f:
        f.write('def get_user(user_id):\n    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n')
    with open(os.path.join(tmp_dir, "requirements.txt"), "w") as f:
        f.write("flask==2.3.2\nrequests==2.31.0\n")
    
    # Security Agent latency (3 runs)
    sec_times = []
    sec_agent = SecurityAnalysisAgent()
    for i in range(3):
        start = time.time()
        try:
            sec_agent.analyze_security(f"latency-{i}", tmp_dir)
        except Exception as e:
            print(f"  Security agent error: {e}")
        sec_times.append((time.time() - start) * 1000)
    results["security_agent"] = {
        "runs": 3,
        "times_ms": [round(t, 1) for t in sec_times],
        "mean_ms": round(statistics.mean(sec_times), 1),
        "std_ms": round(statistics.stdev(sec_times), 1) if len(sec_times) > 1 else 0.0,
    }
    
    # Hallucination Agent latency (3 runs)
    halluc_times = []
    halluc_agent = HallucinationDetectionAgent()
    for i in range(3):
        start = time.time()
        try:
            halluc_agent.detect_hallucinations(f"latency-{i}", tmp_dir)
        except Exception as e:
            print(f"  Hallucination agent error: {e}")
        halluc_times.append((time.time() - start) * 1000)
    results["hallucination_agent"] = {
        "runs": 3,
        "times_ms": [round(t, 1) for t in halluc_times],
        "mean_ms": round(statistics.mean(halluc_times), 1),
        "std_ms": round(statistics.stdev(halluc_times), 1) if len(halluc_times) > 1 else 0.0,
    }
    
    # Dependency Agent latency (3 runs)
    dep_times = []
    dep_agent = DependencyAnalysisAgent()
    for i in range(3):
        start = time.time()
        try:
            dep_agent.analyze_dependencies(f"latency-{i}", tmp_dir)
        except Exception as e:
            print(f"  Dependency agent error: {e}")
        dep_times.append((time.time() - start) * 1000)
    results["dependency_agent"] = {
        "runs": 3,
        "times_ms": [round(t, 1) for t in dep_times],
        "mean_ms": round(statistics.mean(dep_times), 1),
        "std_ms": round(statistics.stdev(dep_times), 1) if len(dep_times) > 1 else 0.0,
    }
    
    # Risk Engine latency (no external deps, 3 runs)
    risk_times = []
    from app.agents.models import DetectionResponse, SecurityAnalysisResponse, DependencyAnalysisResponse
    risk_engine = RiskEngine()
    halluc_resp = DetectionResponse(
        repository_id="latency", total_findings=0, confirmed_findings_count=0,
        likely_findings_count=0, suspicious_findings_count=0, findings=[],
        analysis_duration_ms=0,
    )
    sec_resp = SecurityAnalysisResponse(
        repository_id="latency", total_vulnerabilities=1, critical_count=0,
        high_count=1, medium_count=0, low_count=0, findings=[],
        scan_duration_ms=0,
    )
    dep_resp = DependencyAnalysisResponse(
        repository_id="latency", total_findings=0, critical_count=0,
        high_count=0, medium_count=0, low_count=0, findings=[],
        analysis_duration_ms=0,
    )
    for i in range(3):
        start = time.time()
        try:
            risk_engine.assess_risk(f"latency-{i}", halluc_resp, sec_resp, dep_resp)
        except Exception as e:
            print(f"  Risk engine error: {e}")
        risk_times.append((time.time() - start) * 1000)
    results["risk_engine"] = {
        "runs": 3,
        "times_ms": [round(t, 1) for t in risk_times],
        "mean_ms": round(statistics.mean(risk_times), 1),
        "std_ms": round(statistics.stdev(risk_times), 1) if len(risk_times) > 1 else 0.0,
    }
    
    # Confidence Engine latency (3 runs)
    conf_times = []
    conf_engine = ConfidenceEngine()
    dummy_vr = PatchValidationResult(
        patch_id="latency-test",
        vulnerability_id="v-1",
    )
    for i in range(3):
        start = time.time()
        try:
            conf_engine.calculate_confidence(dummy_vr, historical_success_rate=0.5)
        except Exception as e:
            print(f"  Confidence engine error: {e}")
        conf_times.append((time.time() - start) * 1000)
    results["confidence_engine"] = {
        "runs": 3,
        "times_ms": [round(t, 1) for t in conf_times],
        "mean_ms": round(statistics.mean(conf_times), 1),
        "std_ms": round(statistics.stdev(conf_times), 1) if len(conf_times) > 1 else 0.0,
    }
    
    # End-to-end latency
    e2e_times = []
    for i in range(3):
        start = time.time()
        try:
            sec_agent.analyze_security(f"e2e-{i}", tmp_dir)
            halluc_agent.detect_hallucinations(f"e2e-{i}", tmp_dir)
            dep_agent.analyze_dependencies(f"e2e-{i}", tmp_dir)
            risk_engine.assess_risk(f"e2e-{i}", halluc_resp, sec_resp, dep_resp)
            conf_engine.calculate_confidence(dummy_vr, historical_success_rate=0.5)
        except Exception as e:
            print(f"  E2E error: {e}")
        e2e_times.append((time.time() - start) * 1000)
    results["end_to_end"] = {
        "runs": 3,
        "times_ms": [round(t, 1) for t in e2e_times],
        "mean_ms": round(statistics.mean(e2e_times), 1),
        "std_ms": round(statistics.stdev(e2e_times), 1) if len(e2e_times) > 1 else 0.0,
    }
    
    # Cleanup
    import shutil
    shutil.rmtree(tmp_dir, ignore_errors=True)
    
    return results


def run_ablation_study():
    """Run ablation study: remove each ACE feature and measure impact."""
    print("\n[ABLATION] Running ablation study...")
    
    from app.agents.confidence_engine import ConfidenceEngine
    from app.agents.models import WeightConfig, PatchValidationResult
    
    default_weights = WeightConfig()
    
    # Create a "perfect" validation result
    def make_perfect_vr():
        vr = PatchValidationResult(patch_id="ablation-test", vulnerability_id="v-1")
        vr.compilation_score.score = 1.0
        vr.compilation_score.success = True
        vr.unit_test_score.score = 1.0
        vr.regression_score.score = 1.0
        vr.security_score.score = 1.0
        vr.functional_score.score = 1.0
        vr.performance_score.score = 1.0
        return vr
    
    # Create a "failing" validation result
    def make_failing_vr():
        vr = PatchValidationResult(patch_id="ablation-test", vulnerability_id="v-1")
        vr.compilation_score.score = 0.0
        vr.compilation_score.success = False
        vr.unit_test_score.score = 0.3
        vr.regression_score.score = 0.5
        vr.security_score.score = 0.2
        vr.functional_score.score = 0.4
        vr.performance_score.score = 0.8
        return vr
    
    ablation_results = {}
    
    # Baseline: all features
    engine_full = ConfidenceEngine(weights=default_weights)
    perfect_vr = make_perfect_vr()
    failing_vr = make_failing_vr()
    
    full_perfect = engine_full.calculate_confidence(perfect_vr, 0.5)
    full_failing = engine_full.calculate_confidence(failing_vr, 0.5)
    
    ablation_results["full_model"] = {
        "perfect_confidence": full_perfect.confidence_score,
        "failing_confidence": full_failing.confidence_score,
        "weights": default_weights.to_dict(),
    }
    
    # Ablation: remove each feature (set weight to 0, redistribute)
    feature_names = [
        "static_security", "unit_test_success", "regression_success",
        "compilation_success", "performance", "historical_success",
    ]
    
    for removed_feature in feature_names:
        # Redistribute weight proportionally among remaining features
        remaining = {k: v for k, v in default_weights.to_dict().items() if k != removed_feature}
        total_remaining = sum(remaining.values())
        if total_remaining > 0:
            normalized = {k: v / total_remaining for k, v in remaining.items()}
        else:
            normalized = {k: 1.0 / len(remaining) for k in remaining}
        
        ablation_weights = WeightConfig(**normalized)
        engine_ablation = ConfidenceEngine(weights=ablation_weights)
        
        perfect_result = engine_ablation.calculate_confidence(make_perfect_vr(), 0.5)
        failing_result = engine_ablation.calculate_confidence(make_failing_vr(), 0.5)
        
        delta_perfect = perfect_result.confidence_score - full_perfect.confidence_score
        delta_failing = failing_result.confidence_score - full_failing.confidence_score
        
        ablation_results[f"without_{removed_feature}"] = {
            "perfect_confidence": perfect_result.confidence_score,
            "failing_confidence": failing_result.confidence_score,
            "delta_perfect": round(delta_perfect, 2),
            "delta_failing": round(delta_failing, 2),
            "weights": ablation_weights.to_dict(),
        }
    
    return ablation_results


def format_latex_table_i(sim_table):
    """Format Table I: Simulation Experiment Results as LaTeX."""
    lines = []
    lines.append("\\begin{table}[htbp]")
    lines.append("\\centering")
    lines.append("\\caption{Simulation Experiment Results Across Detection Modes}")
    lines.append("\\label{tab:simulation}")
    lines.append("\\resizebox{\\textwidth}{!}{%")
    lines.append("\\begin{tabular}{lcccccrrrr}")
    lines.append("\\toprule")
    lines.append("Mode & TP & FP & FN & TN & Acc. & Prec. & Recall & F1 & FPR \\\\")
    lines.append("\\midrule")
    
    mode_order = ["STATIC_SCANNER", "LLM_ONLY", "SINGLE_PATCH_LLM", 
                   "MULTI_PATCH_LLM", "MULTI_PATCH_VALIDATION", "HALLUCISHIELD"]
    
    for mode in mode_order:
        if mode in sim_table:
            t = sim_table[mode]
            lines.append(
                f"{mode.replace('_', ' ')} & {t['tp']} & {t['fp']} & {t['fn']} & {t['tn']} "
                f"& {t['accuracy']:.2%} & {t['precision']:.2%} & {t['recall']:.2%} "
                f"& {t['f1']:.2%} & {t['fpr']:.2%} \\\\"
            )
    
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}}")
    lines.append("\\end{table}")
    return "\n".join(lines)


def format_latex_table_ii(real_table):
    """Format Table II: Real Experiment — Per-Category Results as LaTeX."""
    lines = []
    lines.append("\\begin{table}[htbp]")
    lines.append("\\centering")
    lines.append("\\caption{Real Experiment: Per-Category Detection Metrics (HalluciShield)}")
    lines.append("\\label{tab:real_per_category}")
    lines.append("\\resizebox{\\textwidth}{!}{%")
    lines.append("\\begin{tabular}{lcccccrr}")
    lines.append("\\toprule")
    lines.append("Category & $N$ & TP & FP & FN & Prec. & Recall & F1 & Avg Conf. \\\\")
    lines.append("\\midrule")
    
    for cat, data in real_table["per_category"].items():
        lines.append(
            f"{cat.replace('_', ' ')} & {data['test_count']} & {data['tp']} & {data['fp']} "
            f"& {data['fn']} & {data['precision']:.2%} & {data['recall']:.2%} "
            f"& {data['f1']:.2%} & {data['avg_confidence']:.1f} \\\\"
        )
    
    lines.append("\\midrule")
    o = real_table["overall"]
    lines.append(
        f"\\textbf{{Overall}} & {o['total']} & {o['tp']} & {o['fp']} "
        f"& {o['fn']} & {o['precision']:.2%} & {o['recall']:.2%} "
        f"& {o['f1']:.2%} & {o['avg_confidence']:.1f} \\\\"
    )
    
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}}")
    lines.append("\\end{table}")
    return "\n".join(lines)


def format_latex_table_iii(per_cat_table):
    """Format Table III: Per-Category Confusion Matrices (Simulation) as LaTeX."""
    lines = []
    lines.append("\\begin{table}[htbp]")
    lines.append("\\centering")
    lines.append("\\caption{Per-Category Detection Metrics (Simulation, HalluciShield Mode)}")
    lines.append("\\label{tab:per_category_sim}")
    lines.append("\\begin{tabular}{lcccccc}")
    lines.append("\\toprule")
    lines.append("Category & TP & FP & FN & TN & Prec. & Recall & F1 \\\\")
    lines.append("\\midrule")
    
    for cat, cm in per_cat_table.items():
        lines.append(
            f"{cat.replace('_', ' ')} & {cm['tp']} & {cm['fp']} & {cm['fn']} & {cm['tn']} "
            f"& {cm['precision']:.2%} & {cm['recall']:.2%} & {cm['f1']:.2%} \\\\"
        )
    
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    lines.append("\\end{table}")
    return "\n".join(lines)


def format_latex_table_iv(real_mode_table):
    """Format Table IV: Real Experiment — Per-Mode Comparison as LaTeX."""
    lines = []
    lines.append("\\begin{table}[htbp]")
    lines.append("\\centering")
    lines.append("\\caption{Real Experiment: Per-Mode Comparison (9 Benchmark Cases)}")
    lines.append("\\label{tab:real_per_mode}")
    lines.append("\\begin{tabular}{lccccccr}")
    lines.append("\\toprule")
    lines.append("Mode & $N$ & TP & FP & FN & Acc. & Prec. & Recall & F1 \\\\")
    lines.append("\\midrule")
    
    mode_order = ["STATIC_SCANNER", "LLM_ONLY", "SINGLE_PATCH_LLM",
                   "MULTI_PATCH_LLM", "MULTI_PATCH_VALIDATION", "HALLUCISHIELD"]
    
    for mode in mode_order:
        if mode in real_mode_table:
            t = real_mode_table[mode]
            lines.append(
                f"{mode.replace('_', ' ')} & {t['test_count']} & {t['tp']} & {t['fp']} & {t['fn']} "
                f"& {t['accuracy']:.2%} & {t['precision']:.2%} & {t['recall']:.2%} "
                f"& {t['f1']:.2%} \\\\"
            )
    
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    lines.append("\\end{table}")
    return "\n".join(lines)


def format_latex_table_latency(latency):
    """Format Table V: Latency Benchmark as LaTeX."""
    lines = []
    lines.append("\\begin{table}[htbp]")
    lines.append("\\centering")
    lines.append("\\caption{Per-Agent Latency Benchmarks (3 runs, mean $\\pm$ std)}")
    lines.append("\\label{tab:latency}")
    lines.append("\\begin{tabular}{lrr}")
    lines.append("\\toprule")
    lines.append("Component & Mean (ms) & Std (ms) \\\\")
    lines.append("\\midrule")
    
    for agent_name, data in latency.items():
        label = agent_name.replace("_", " ").title()
        lines.append(f"{label} & {data['mean_ms']:.1f} & $\\pm${data['std_ms']:.1f} \\\\")
    
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    lines.append("\\end{table}")
    return "\n".join(lines)


def format_latex_table_ablation(ablation):
    """Format Table VI: Ablation Study as LaTeX."""
    lines = []
    lines.append("\\begin{table}[htbp]")
    lines.append("\\centering")
    lines.append("\\caption{ACE Ablation Study: Impact of Removing Each Feature}")
    lines.append("\\label{tab:ablation}")
    lines.append("\\begin{tabular}{lrrr}")
    lines.append("\\toprule")
    lines.append("Configuration & Perfect (\\%) & Failing (\\%) & $\\Delta$ Perfect \\\\")
    lines.append("\\midrule")
    
    full = ablation["full_model"]
    lines.append(
        f"Full Model & {full['perfect_confidence']:.1f} & {full['failing_confidence']:.1f} & --- \\\\"
    )
    lines.append("\\midrule")
    
    for key, data in ablation.items():
        if key == "full_model":
            continue
        feature = key.replace("without_", "").replace("_", " ").title()
        lines.append(
            f"Without {feature} & {data['perfect_confidence']:.1f} & {data['failing_confidence']:.1f} "
            f"& {data['delta_perfect']:+.1f} \\\\"
        )
    
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    lines.append("\\end{table}")
    return "\n".join(lines)


def main():
    print("=" * 70)
    print("  HalluciShield Experimental Evaluation")
    print(f"  Date: {datetime.now().isoformat()}")
    print(f"  Dataset: {DATASET_VERSION} ({len(ALL_TEST_CASES)} cases), Real: {REAL_BENCHMARK_VERSION} ({len(REAL_BENCHMARK_CASES)} cases)")
    print("=" * 70)
    
    # Run experiments
    sim_run = run_simulation_experiment()
    real_run_hallucishield = run_real_experiment()
    real_run_all_modes = run_real_experiment_all_modes()
    
    # Produce tables
    sim_table = produce_simulation_table(sim_run)
    real_table = produce_real_table(real_run_hallucishield)
    per_cat_sim = produce_per_category_simulation_table(sim_run)
    real_mode_table = produce_real_per_mode_table(real_run_all_modes)
    
    # Latency and ablation
    latency = run_latency_benchmark()
    ablation = run_ablation_study()
    
    # Save raw results
    with open(RAW_DIR / "simulation_experiment.json", "w") as f:
        json.dump(sim_table, f, indent=2)
    with open(RAW_DIR / "real_experiment_hallucishield.json", "w") as f:
        json.dump(real_table, f, indent=2)
    with open(RAW_DIR / "real_experiment_all_modes.json", "w") as f:
        json.dump(real_mode_table, f, indent=2)
    with open(RAW_DIR / "per_category_simulation.json", "w") as f:
        json.dump(per_cat_sim, f, indent=2)
    with open(LATENCY_DIR / "latency_benchmarks.json", "w") as f:
        json.dump(latency, f, indent=2)
    with open(ABLATION_DIR / "ablation_results.json", "w") as f:
        json.dump(ablation, f, indent=2)
    
    # Save confusion matrices
    for cat in CATEGORIES:
        cm = compute_confusion_matrix(sim_run.records, ExperimentMode.HALLUCISHIELD, category=cat)
        with open(CM_DIR / f"sim_{cat}.json", "w") as f:
            json.dump(cm, f, indent=2)
    
    # Generate LaTeX tables
    latex_tables = []
    latex_tables.append(format_latex_table_i(sim_table))
    latex_tables.append("")
    latex_tables.append(format_latex_table_ii(real_table))
    latex_tables.append("")
    latex_tables.append(format_latex_table_iii(per_cat_sim))
    latex_tables.append("")
    latex_tables.append(format_latex_table_iv(real_mode_table))
    latex_tables.append("")
    latex_tables.append(format_latex_table_latency(latency))
    latex_tables.append("")
    latex_tables.append(format_latex_table_ablation(ablation))
    
    with open(PROCESSED_DIR / "ieee_tables.tex", "w") as f:
        f.write("\n".join(latex_tables))
    
    # Print summary
    print("\n" + "=" * 70)
    print("  EVALUATION COMPLETE")
    print("=" * 70)
    
    print("\n--- Table I: Simulation Results ---")
    for mode, t in sim_table.items():
        print(f"  {mode:30s}  Acc={t['accuracy']:.2%}  Prec={t['precision']:.2%}  Recall={t['recall']:.2%}  F1={t['f1']:.2%}")
    
    print("\n--- Table II: Real Experiment (HalluciShield) ---")
    for cat, data in real_table["per_category"].items():
        print(f"  {cat:30s}  Prec={data['precision']:.2%}  Recall={data['recall']:.2%}  F1={data['f1']:.2%}")
    o = real_table["overall"]
    print(f"  {'OVERALL':30s}  Prec={o['precision']:.2%}  Recall={o['recall']:.2%}  F1={o['f1']:.2%}")
    
    print("\n--- Table IV: Real Experiment Per-Mode ---")
    for mode, t in real_mode_table.items():
        print(f"  {mode:30s}  Acc={t['accuracy']:.2%}  Prec={t['precision']:.2%}  Recall={t['recall']:.2%}  F1={t['f1']:.2%}")
    
    print("\n--- Latency ---")
    for agent, data in latency.items():
        print(f"  {agent:30s}  {data['mean_ms']:.1f} +/- {data['std_ms']:.1f} ms")
    
    print("\n--- Ablation (Perfect case) ---")
    for key, data in ablation.items():
        label = key.replace("without_", "w/o ").replace("_", " ")
        print(f"  {label:30s}  {data['perfect_confidence']:.1f}%")
    
    print(f"\nResults saved to: {EVAL_DIR}")
    print(f"LaTeX tables: {PROCESSED_DIR / 'ieee_tables.tex'}")
    print("=" * 70)


if __name__ == "__main__":
    main()
