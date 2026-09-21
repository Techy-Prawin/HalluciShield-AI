"""
Patch Generation Agent API Router.

Provides HTTP endpoints for:
- Multi-candidate patch generation
- Secure patch validation in isolated Docker sandbox
- Validation Agent (6 independent scoring dimensions)
- Adaptive Confidence Engine (patch ranking)
"""

from fastapi import APIRouter, HTTPException, status

from app.agents.patch_agent import PatchGenerationAgent
from app.agents.sandbox_agent import SandboxAgent
from app.agents.validation_agent import ValidationAgent
from app.agents.confidence_engine import ConfidenceService
from app.agents.patch_ranker import PatchRanker
from app.api.learning import engine as learning_engine
from app.agents.models import (
    PatchGenerationRequest,
    PatchGenerationResponse,
    SandboxStatus,
    SandboxValidationRequest,
    SandboxValidationResponse,
    ValidateCandidatesRequest,
    ValidateCandidatesResponse,
    RankPatchesRequest,
    RankPatchesResponse,
)

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["Patch Generation Agent"])

agent_instance = PatchGenerationAgent()
sandbox_instance = None
validation_instance = ValidationAgent()
confidence_service = ConfidenceService()
ranker = PatchRanker(adaptive_learning_engine=learning_engine)


def _get_sandbox_agent() -> SandboxAgent:
    """Lazy-initialize sandbox agent."""
    global sandbox_instance
    if sandbox_instance is None:
        try:
            sandbox_instance = SandboxAgent()
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Sandbox unavailable: {str(e)}",
            )
    return sandbox_instance


@router.post(
    "/{vulnerability_id}/generate-patches",
    response_model=PatchGenerationResponse,
    status_code=status.HTTP_200_OK,
)
async def generate_patches_endpoint(
    vulnerability_id: str,
    request: PatchGenerationRequest,
):
    """
    Generate exactly 5 candidate patches for a vulnerability.

    Each candidate is a suggestion only -- NOT a claim of security.

    Returns structured PatchGenerationResponse with candidates, timing,
    model used, and retry count.
    """
    if request.vulnerability_id != vulnerability_id:
        request.vulnerability_id = vulnerability_id

    if not request.vulnerable_code.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="vulnerable_code is required and must not be empty",
        )

    try:
        response = agent_instance.generate_patches(request)
        return response
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Patch generation failed: {str(e)}",
        )


@router.post(
    "/{vulnerability_id}/validate-patch",
    response_model=SandboxValidationResponse,
    status_code=status.HTTP_200_OK,
)
async def validate_patch_endpoint(
    vulnerability_id: str,
    request: SandboxValidationRequest,
):
    """
    Validate a candidate patch in an isolated Docker sandbox.

    Each patch runs in its own container with:
    - Network isolation (--net=none)
    - Non-root user execution (UID 10001)
    - CPU limit (configurable, default 1.0 cores)
    - Memory limit (configurable, default 512MB)
    - Execution timeout (configurable, default 30s)
    - Temporary filesystem (tmpfs)
    - Process limits (configurable, default 64)
    - Automatic container cleanup

    Returns SandboxValidationResponse with compilation, test, security scan,
    and performance results.
    """
    if not request.original_code.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="original_code is required and must not be empty",
        )

    if not request.file_path.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="file_path is required and must not be empty",
        )

    try:
        sandbox = _get_sandbox_agent()
        response = sandbox.validate_patch(request)
        response.sandbox_status = (
            SandboxStatus.AVAILABLE if sandbox.is_available() else SandboxStatus.NOT_AVAILABLE
        )
        return response
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Sandbox validation failed: {str(e)}",
        )


@router.post(
    "/{vulnerability_id}/validate-candidates",
    response_model=ValidateCandidatesResponse,
    status_code=status.HTTP_200_OK,
)
async def validate_candidates_endpoint(
    vulnerability_id: str,
    request: ValidateCandidatesRequest,
):
    """
    Validate multiple candidate patches across 6 independent dimensions:

    1. Compilation - Does the patched code compile?
    2. Unit Tests - Do unit tests pass?
    3. Regression Tests - Are there any regressions?
    4. Security Scan - Are there new vulnerabilities?
    5. Functional Behavior - Is the original behavior preserved?
    6. Performance Impact - Is there a performance regression?

    Each dimension produces an independent score from 0.0 to 1.0.
    The final confidence score is NOT calculated here.

    Stores all validation results in PostgreSQL.
    """
    if request.vulnerability_id != vulnerability_id:
        request.vulnerability_id = vulnerability_id

    if not request.candidates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one candidate patch is required",
        )

    try:
        # Run validation
        response = validation_instance.validate_candidates(request)

        # Store results in PostgreSQL
        from app.agents.database import store_validation_results_batch
        try:
            import asyncio
            results_for_storage = []
            for result in response.results:
                results_for_storage.append({
                    "vulnerability_id": result.vulnerability_id,
                    "patch_id": result.patch_id,
                    "validation_status": result.validation_status.value,
                    "compilation_score": result.compilation_score.score,
                    "unit_test_score": result.unit_test_score.score,
                    "regression_score": result.regression_score.score,
                    "security_score": result.security_score.score,
                    "functional_score": result.functional_score.score,
                    "performance_score": result.performance_score.score,
                    "details": {
                        "compilation": result.compilation_score.model_dump(),
                        "unit_test": result.unit_test_score.model_dump(),
                        "regression": result.regression_score.model_dump(),
                        "security": result.security_score.model_dump(),
                        "functional": result.functional_score.model_dump(),
                        "performance": result.performance_score.model_dump(),
                    },
                })

            try:
                loop = asyncio.get_running_loop()
                asyncio.ensure_future(
                    store_validation_results_batch(results_for_storage)
                )
            except RuntimeError:
                asyncio.run(
                    store_validation_results_batch(results_for_storage)
                )
        except Exception as e:
            # Log but don't fail the request
            pass

        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Validation failed: {str(e)}",
        )


@router.post(
    "/{vulnerability_id}/rank-patches",
    response_model=RankPatchesResponse,
    status_code=status.HTTP_200_OK,
)
async def rank_patches_endpoint(
    vulnerability_id: str,
    request: RankPatchesRequest,
):
    """
    Rank candidate patches using the Adaptive Confidence Engine.

    Calculates confidence scores based on:
    - Static Security Improvement (25%)
    - Unit Test Success (20%)
    - Regression Test Success (20%)
    - Compilation Success (10%)
    - Performance (10%)
    - Historical Success (15%)

    The calculation is deterministic and reproducible.
    LLM reasoning is stored as supporting evidence only.

    Returns ranked patches with:
    - Final confidence score (0-100%)
    - Individual feature scores
    - Weights used
    - Positive and negative evidence
    - Validation failures
    - Recommendation

    Stores all results in PostgreSQL for research experiments.
    """
    if request.vulnerability_id != vulnerability_id:
        request.vulnerability_id = vulnerability_id

    if not request.validation_results:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one validation result is required for ranking",
        )

    try:
        # Resolve historical success rates from learning engine
        historical_rates = ranker._resolve_historical_rates(request)

        # Use request-level weights if provided, otherwise default to global engine
        from app.agents.confidence_engine import ConfidenceEngine
        engine = ranker.engine
        if request.weights is not None:
            engine = ConfidenceEngine(weights=request.weights)

        # Calculate confidence for each patch using resolved historical rates
        from app.agents.models import ConfidenceRanking
        confidence_results = []
        for vr in request.validation_results:
            hist_rate = 0.5
            if historical_rates and vr.patch_id in historical_rates:
                hist_rate = historical_rates[vr.patch_id]
            cr = engine.calculate_confidence(vr, historical_success_rate=hist_rate)
            if not cr.vulnerability_id and vulnerability_id:
                cr = cr.model_copy(update={"vulnerability_id": vulnerability_id})
            confidence_results.append(cr)
        confidence_results.sort(key=lambda x: x.confidence_score, reverse=True)

        best_patch = confidence_results[0].patch_id if confidence_results else None
        ranking = ConfidenceRanking(
            vulnerability_id=vulnerability_id,
            rankings=confidence_results,
            total_patches=len(confidence_results),
            best_patch_id=best_patch,
            weights_used=engine.weights.model_dump(),
        )

        response = RankPatchesResponse(
            vulnerability_id=vulnerability_id,
            ranking=ranking,
        )

        # Store results in PostgreSQL
        from app.agents.database import (
            store_confidence_results_batch,
            store_confidence_history,
        )
        try:
            import asyncio
            results_for_storage = []
            for cr in response.ranking.rankings:
                feature_dict = {
                    f.feature.value: {
                        "raw_value": f.raw_value,
                        "normalized_value": f.normalized_value,
                        "weight": f.weight,
                        "weighted_score": f.weighted_score,
                        "evidence": f.evidence,
                        "is_penalty": f.is_penalty,
                        "penalty_reason": f.penalty_reason,
                    }
                    for f in cr.feature_scores
                }
                results_for_storage.append({
                    "vulnerability_id": cr.vulnerability_id,
                    "patch_id": cr.patch_id,
                    "confidence_score": cr.confidence_score,
                    "feature_scores": feature_dict,
                    "weights_used": cr.weights_used.to_dict(),
                    "positive_evidence": cr.positive_evidence,
                    "negative_evidence": cr.negative_evidence,
                    "validation_failures": cr.validation_failures,
                    "recommendation": cr.recommendation,
                    "algorithm_version": cr.algorithm_version,
                })

            try:
                loop = asyncio.get_running_loop()
                asyncio.ensure_future(
                    store_confidence_results_batch(results_for_storage)
                )
                for cr_data in results_for_storage:
                    asyncio.ensure_future(
                        store_confidence_history(cr_data)
                    )
            except RuntimeError:
                asyncio.run(
                    store_confidence_results_batch(results_for_storage)
                )
                for cr_data in results_for_storage:
                    asyncio.run(
                        store_confidence_history(cr_data)
                    )
        except Exception as e:
            # Log but don't fail the request
            pass

        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Confidence calculation failed: {str(e)}",
        )
