"""
Analytics API endpoint that prepares experiment data as chart-ready JSON.
Every chart is sourced from stored experiment data — no fake/demo data.
Supports both SIMULATION and REAL experiment data with explicit labeling.
"""
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, HTTPException

from app.agents.experiment_runner import experiment_runner, _filter_test_cases
from app.agents.models import VulnerabilityTestCategory, ExperimentMode, ExperimentDataSource
from app.agents.test_dataset import ALL_TEST_CASES, ALL_TEST_CASES_BY_CATEGORY

router = APIRouter(prefix="/api/analytics", tags=["analytics"])


def _build_analytics_payload(experiment_id: str) -> dict:
    run = next((r for r in experiment_runner.completed_runs if r.experiment_id == experiment_id), None)
    if not run:
        raise HTTPException(status_code=404, detail="Experiment not found")

    modes = list(run.config.modes)
    records = run.records
    metrics_map = run.metrics_by_mode
    data_source = run.data_source.value

    detection_accuracy = []
    hallucination_pr = []
    patch_success = []
    regression_data = []
    confidence_data = []
    validation_time = []
    baseline_comparison = []
    scatter_data = []
    security_improvement = []

    for mode_enum in modes:
        mode_key = mode_enum.value
        m = metrics_map.get(mode_key)
        if not m:
            continue

        detection_accuracy.append({
            "mode": mode_key,
            "data_source": data_source,
            "accuracy": round(m.detection_accuracy * 100, 2),
            "precision": round(m.precision * 100, 2),
            "recall": round(m.recall * 100, 2),
        })

        hallucination_pr.append({
            "mode": mode_key,
            "data_source": data_source,
            "precision": round(m.precision * 100, 2),
            "recall": round(m.recall * 100, 2),
            "f1": round(m.f1 * 100, 2),
        })

        patch_success.append({
            "mode": mode_key,
            "data_source": data_source,
            "patch_success_rate": round(m.patch_success_rate * 100, 2),
            "total_patches": m.total_patches_generated,
            "validated": m.total_patches_validated,
        })

        regression_data.append({
            "mode": mode_key,
            "data_source": data_source,
            "regression_rate": round(m.regression_rate * 100, 2),
            "regressions": int(m.regression_rate * m.total_patches_validated) if m.total_patches_validated > 0 else 0,
        })

        confidence_data.append({
            "mode": mode_key,
            "data_source": data_source,
            "avg_confidence": round(m.confidence_calibration * 100, 2),
        })

        validation_time.append({
            "mode": mode_key,
            "data_source": data_source,
            "avg_validation_time_ms": round(m.avg_validation_time_ms, 1),
        })

    mode_records = [r for r in records if r.mode in modes]
    for r in mode_records:
        if r.generated_patches_count > 0:
            scatter_data.append({
                "test_id": r.test_id,
                "confidence": round(r.best_confidence_score * 100, 2),
                "success": 100 if r.patch_success else 0,
                "mode": r.mode.value,
                "data_source": data_source,
            })

    static_key = ExperimentMode.STATIC_SCANNER.value
    hs_key = ExperimentMode.HALLUCISHIELD.value
    m_static = metrics_map.get(static_key)
    m_hs = metrics_map.get(hs_key)
    if m_static and m_hs:
        baseline_comparison.append({
            "metric": "Detection Accuracy",
            "STATIC_SCANNER": round(m_static.detection_accuracy * 100, 2),
            "HALLUCISHIELD": round(m_hs.detection_accuracy * 100, 2),
        })
        baseline_comparison.append({
            "metric": "Precision",
            "STATIC_SCANNER": round(m_static.precision * 100, 2),
            "HALLUCISHIELD": round(m_hs.precision * 100, 2),
        })
        baseline_comparison.append({
            "metric": "Recall",
            "STATIC_SCANNER": round(m_static.recall * 100, 2),
            "HALLUCISHIELD": round(m_hs.recall * 100, 2),
        })
        baseline_comparison.append({
            "metric": "F1 Score",
            "STATIC_SCANNER": round(m_static.f1 * 100, 2),
            "HALLUCISHIELD": round(m_hs.f1 * 100, 2),
        })
        baseline_comparison.append({
            "metric": "Patch Success",
            "STATIC_SCANNER": round(m_static.patch_success_rate * 100, 2),
            "HALLUCISHIELD": round(m_hs.patch_success_rate * 100, 2),
        })

    for cat in VulnerabilityTestCategory:
        cat_records = [r for r in records if r.vuln_category == cat and r.mode == ExperimentMode.HALLUCISHIELD]
        if cat_records:
            total = len(cat_records)
            detected = sum(1 for r in cat_records if r.detection_result)
            patched = sum(1 for r in cat_records if r.patch_success)
            security_improvement.append({
                "category": cat.value,
                "data_source": data_source,
                "before_patch": round((detected / total) * 100, 2) if total > 0 else 0,
                "after_patch": round((patched / total) * 100, 2) if total > 0 else 0,
            })

    return {
        "experiment_id": experiment_id,
        "experiment_name": run.config.experiment_name,
        "data_source": data_source,
        "dataset_version": run.config.dataset_version,
        "dataset_hash": run.dataset_hash,
        "total_test_cases": len(ALL_TEST_CASES),
        "modes_compared": [m.value for m in modes],
        "charts": {
            "detection_accuracy": detection_accuracy,
            "hallucination_precision_recall": hallucination_pr,
            "patch_success_rate": patch_success,
            "regression_rate": regression_data,
            "average_confidence": confidence_data,
            "confidence_vs_success": scatter_data,
            "baseline_comparison": baseline_comparison,
            "validation_time": validation_time,
            "security_improvement": security_improvement,
        },
        "data_provenance": {
            "source": "stored_experiment_data",
            "data_source": data_source,
            "experiment_id": experiment_id,
            "records_used": len(records),
            "note": (
                "SIMULATION: deterministic category-based lookups. No synthetic data injected." if data_source == "SIMULATION"
                else "REAL: actual HalluciShield pipeline agents executed on controlled test cases. No simulated data."
            ),
        },
    }


@router.get("/latest/charts")
async def get_latest_charts():
    if not experiment_runner.completed_runs:
        raise HTTPException(
            status_code=404,
            detail="No experiments have been run yet. POST /api/experiments/run first.",
        )
    latest = experiment_runner.completed_runs[-1]
    return _build_analytics_payload(latest.experiment_id)


@router.get("/{experiment_id}/charts")
async def get_experiment_charts(experiment_id: str):
    return _build_analytics_payload(experiment_id)
