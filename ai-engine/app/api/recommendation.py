"""
Patch Ranking & Recommendation API Router.

Provides HTTP endpoints for:
- POST /api/v1/vulnerabilities/:id/recommendation
- POST /api/v1/vulnerabilities/:id/patches/:patch_id/explanation

Returns ranked patches with confidence scores and recommendation.
Returns detailed explanations from stored evidence (no LLM fabrication).
"""

from fastapi import APIRouter, HTTPException, Query, status

from app.agents.patch_ranker import PatchRanker
from app.agents.explanation_generator import ExplanationGenerator
from app.agents.models import (
    ExplanationResponse,
    PatchExplanation,
    PatchValidationResult,
    RankPatchesRequest,
    RecommendationResponse,
)

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["Patch Ranking & Recommendation"])

ranker_instance = PatchRanker()
explanation_generator = ExplanationGenerator()


@router.post(
    "/{vulnerability_id}/recommendation",
    response_model=RecommendationResponse,
    status_code=status.HTTP_200_OK,
)
async def post_recommendation_endpoint(
    vulnerability_id: str,
    request: RankPatchesRequest,
    safety_threshold: float = Query(default=50.0, ge=0.0, le=100.0),
):
    """
    POST version for convenience when request body is large.

    Same behavior as GET recommendation.
    """
    if request.vulnerability_id != vulnerability_id:
        request.vulnerability_id = vulnerability_id

    if not request.validation_results:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one validation_result is required for recommendation",
        )

    try:
        ranker = PatchRanker(safety_threshold=safety_threshold)
        response = ranker.get_recommendation(
            vulnerability_id=vulnerability_id,
            validation_results=request.validation_results,
            historical_success_rates=request.historical_success_rates,
        )
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Recommendation failed: {str(e)}",
        )


@router.post(
    "/{vulnerability_id}/patches/{patch_id}/explanation",
    response_model=ExplanationResponse,
    status_code=status.HTTP_200_OK,
)
async def get_patch_explanation_endpoint(
    vulnerability_id: str,
    patch_id: str,
    request: RankPatchesRequest,
    safety_threshold: float = Query(default=50.0, ge=0.0, le=100.0),
):
    """
    Get detailed explanation for why a specific patch is recommended.

    Generates explanation from stored validation evidence. No LLM is used.

    Returns:
    - Why This Patch (checklist of passed/failed validations)
    - Confidence Score with feature contributions
    - Validation evidence from stored results
    - Before/after security findings comparison

    All explanation content is derived from PatchValidationResult
    and ConfidenceResult evidence. No fabricated results.
    """
    if not request.validation_results:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="validation_results required for explanation",
        )

    target_vr = next(
        (vr for vr in request.validation_results if vr.patch_id == patch_id),
        None,
    )
    if target_vr is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch {patch_id} not found in validation results",
        )

    try:
        explanation = explanation_generator.generate_explanation(
            validation_result=target_vr,
            vulnerability_id=vulnerability_id,
            safety_threshold=safety_threshold,
            historical_success_rate=0.5,
        )
        return ExplanationResponse(
            vulnerability_id=vulnerability_id,
            patch_id=patch_id,
            explanation=explanation,
            status="success",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Explanation generation failed: {str(e)}",
        )
