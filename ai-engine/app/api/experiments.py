"""
Research experiment API endpoints.
Provides endpoints for running experiments, querying results, and exporting.
Supports both SIMULATION and REAL experiment modes.
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from app.agents.experiment_runner import experiment_runner
from app.agents.models import ExperimentDataSource, RunExperimentRequest, VulnerabilityTestCategory
from app.security import require_api_key

router = APIRouter(
    prefix="/api/experiments",
    tags=["experiments"],
    dependencies=[Depends(require_api_key)],
)


@router.post("/run")
async def run_experiment(request: RunExperimentRequest):
    run = experiment_runner.run_experiment(request)
    return {
        "experiment_id": run.experiment_id,
        "status": run.status,
        "data_source": run.data_source.value,
        "duration_ms": run.duration_ms,
        "dataset_hash": run.dataset_hash,
        "modes_run": list(run.metrics_by_mode.keys()),
    }


@router.post("/run-real")
async def run_real_experiment(request: RunExperimentRequest):
    request.data_source = ExperimentDataSource.REAL
    run = experiment_runner.run_experiment(request)
    return {
        "experiment_id": run.experiment_id,
        "status": run.status,
        "data_source": "REAL",
        "duration_ms": run.duration_ms,
        "dataset_hash": run.dataset_hash,
        "modes_run": list(run.metrics_by_mode.keys()),
        "total_records": len(run.records),
    }


@router.get("/list")
async def list_experiments():
    summaries = experiment_runner.list_experiments()
    return {"experiments": [s.model_dump() for s in summaries]}


@router.get("/{experiment_id}/summary")
async def get_experiment_summary(experiment_id: str):
    summary = experiment_runner.get_summary(experiment_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Experiment not found")
    return summary.model_dump()


@router.get("/{experiment_id}/metrics")
async def get_experiment_metrics(experiment_id: str):
    run = next((r for r in experiment_runner.completed_runs if r.experiment_id == experiment_id), None)
    if not run:
        raise HTTPException(status_code=404, detail="Experiment not found")
    return {
        "data_source": run.data_source.value,
        "metrics": {k: v.model_dump() for k, v in run.metrics_by_mode.items()},
    }


@router.get("/{experiment_id}/export")
async def export_experiment_results(experiment_id: str, format: str = "json"):
    result = experiment_runner.export_results(experiment_id, format)
    if not result:
        raise HTTPException(status_code=404, detail="Experiment not found")
    return result


@router.get("/categories")
async def get_categories():
    return {
        "categories": [cat.value for cat in VulnerabilityTestCategory],
        "modes": [
            "LLM_ONLY", "STATIC_SCANNER", "SINGLE_PATCH_LLM",
            "MULTI_PATCH_LLM", "MULTI_PATCH_VALIDATION", "HALLUCISHIELD",
        ],
        "data_sources": ["SIMULATION", "REAL"],
    }
