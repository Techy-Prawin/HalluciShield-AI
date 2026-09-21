"""
Adaptive Learning Engine API Router.

Provides HTTP endpoints for:
- POST /api/v1/learning/record
- POST /api/v1/learning/deployment-outcome
- GET /api/v1/learning/patterns
- GET /api/v1/learning/patterns/{vuln_type}
- GET /api/v1/learning/summary
- GET /api/v1/learning/explain/{vuln_type}/{strategy}
- POST /api/v1/learning/suggest-weights
- GET /api/v1/learning/adjustments
- GET /api/v1/learning/records
"""

from fastapi import APIRouter, HTTPException, Query, status

from app.agents.adaptive_learning import AdaptiveLearningEngine
from app.agents.models import (
    LearningDashboard,
    LearningPattern,
    LearningRecord,
    RecordDeploymentOutcomeRequest,
    RecordLearningRequest,
    WeightAdjustment,
    WeightConfig,
)

router = APIRouter(prefix="/api/v1/learning", tags=["Adaptive Learning Engine"])

engine = AdaptiveLearningEngine()


@router.post(
    "/record",
    response_model=LearningRecord,
    status_code=status.HTTP_201_CREATED,
)
async def record_learning_event_endpoint(request: RecordLearningRequest):
    """Record a learning event from developer feedback or validation."""
    try:
        record = engine.record_learning_event(request)
        return record
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to record learning event: {str(e)}",
        )


@router.post(
    "/deployment-outcome",
    status_code=status.HTTP_200_OK,
)
async def record_deployment_outcome_endpoint(
    request: RecordDeploymentOutcomeRequest,
):
    """Record post-deployment outcome for an existing learning record."""
    record = engine.record_deployment_outcome(request)
    if record:
        return {
            "status": "success",
            "message": f"Deployment outcome recorded for patch {request.patch_id}",
            "record": record.model_dump(),
        }
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"No learning record found for vuln={request.vulnerability_id}, patch={request.patch_id}",
    )


@router.get(
    "/patterns",
    response_model=list,
    status_code=status.HTTP_200_OK,
)
async def get_patterns_endpoint():
    """Get all extracted patterns sorted by sample count."""
    patterns = engine.get_all_patterns()
    return [p.model_dump() for p in patterns]


@router.get(
    "/patterns/{vulnerability_type}",
    response_model=list,
    status_code=status.HTTP_200_OK,
)
async def get_patterns_for_vulnerability_endpoint(vulnerability_type: str):
    """Get patterns for a specific vulnerability type."""
    patterns = engine.get_patterns_for_vulnerability(vulnerability_type)
    return [p.model_dump() for p in patterns]


@router.get(
    "/summary",
    response_model=LearningDashboard,
    status_code=status.HTTP_200_OK,
)
async def get_summary_endpoint():
    """Get learning dashboard summary."""
    return engine.get_summary()


@router.get(
    "/explain/{vulnerability_type}/{patch_strategy}",
    status_code=status.HTTP_200_OK,
)
async def explain_weight_endpoint(vulnerability_type: str, patch_strategy: str):
    """Get explainable weight calculation for a specific (vuln_type, strategy) pair."""
    return engine.explain_weight_calculation(vulnerability_type, patch_strategy)


@router.post(
    "/suggest-weights",
    status_code=status.HTTP_200_OK,
)
async def suggest_weights_endpoint():
    """Suggest weight adjustments based on extracted patterns."""
    current_weights = WeightConfig()
    adjustment, message = engine.suggest_weight_adjustment(current_weights)
    if adjustment:
        return {
            "status": "success",
            "message": message,
            "adjustment": adjustment.model_dump(),
        }
    return {
        "status": "no_adjustment",
        "message": message,
        "adjustment": None,
    }


@router.post(
    "/apply-adjustment",
    status_code=status.HTTP_200_OK,
)
async def apply_adjustment_endpoint(adjustment: WeightAdjustment):
    """Apply a weight adjustment (must be approved by developer)."""
    engine.apply_weight_adjustment(adjustment)
    return {
        "status": "success",
        "message": f"Adjustment applied. New model version: {engine.model_version}",
        "model_version": engine.model_version,
    }


@router.get(
    "/adjustments",
    response_model=list,
    status_code=status.HTTP_200_OK,
)
async def get_adjustments_endpoint():
    """Get weight adjustment history."""
    adjustments = engine.get_adjustment_history()
    return [a.model_dump() for a in adjustments]


@router.get(
    "/records",
    response_model=list,
    status_code=status.HTTP_200_OK,
)
async def get_records_endpoint(
    vulnerability_type: str = Query(default=None),
    patch_strategy: str = Query(default=None),
):
    """Get learning records with optional filters."""
    records = engine.get_records(
        vulnerability_type=vulnerability_type,
        patch_strategy=patch_strategy,
    )
    return [r.model_dump() for r in records]
