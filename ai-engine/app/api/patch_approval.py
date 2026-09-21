"""
Human-in-the-Loop Patch Approval API Router.

Provides HTTP endpoints for:
- GET /api/v1/vulnerabilities/:id/patches/:patch_id/review
- POST /api/v1/vulnerabilities/:id/patches/:patch_id/approve
- POST /api/v1/vulnerabilities/:id/patches/:patch_id/reject
- GET /api/v1/vulnerabilities/:id/approvals
- GET /api/v1/vulnerabilities/:id/patches/:patch_id/approval-status

Design principle: Never automatically deploy a generated patch.
Developer approval is mandatory.
"""

from fastapi import APIRouter, HTTPException, Query, Request, status

from app.agents.patch_approval import PatchApprovalService
from app.agents.models import (
    ApprovePatchRequest,
    PatchApprovalResponse,
    PatchApprovalRecord,
    PatchReviewResponse,
    RejectPatchRequest,
    PatchCandidate,
    PatchValidationResult,
)
from app.security import require_api_key

router = APIRouter(
    prefix="/api/v1/vulnerabilities",
    tags=["Human-in-the-Loop Patch Approval"],
)

approval_service = PatchApprovalService()


@router.get(
    "/{vulnerability_id}/patches/{patch_id}/review",
    response_model=PatchReviewResponse,
    status_code=status.HTTP_200_OK,
)
async def get_patch_review_endpoint(
    vulnerability_id: str,
    patch_id: str,
    original_code: str = Query(default="", description="Original source code before patch"),
    patched_code: str = Query(default="", description="Patched source code"),
    vulnerability_type: str = Query(default="", description="Type of vulnerability"),
    vulnerability_description: str = Query(default="", description="Description of vulnerability"),
    vulnerability_severity: str = Query(default="", description="Severity of vulnerability"),
    security_strategy: str = Query(default="", description="Security strategy used in patch"),
    safety_threshold: float = Query(default=50.0, ge=0.0, le=100.0),
    historical_success_rate: float = Query(default=0.5, ge=0.0, le=1.0),
):
    """
    Get full review context for a patch before developer decision.

    Shows:
    - Original code
    - Patched code
    - Diff between them
    - Vulnerability details
    - Validation results
    - Confidence score
    - Explanation
    """
    try:
        patch_candidate = None
        if patched_code:
            patch_candidate = PatchCandidate(
                patch_id=patch_id,
                modified_code=patched_code,
                explanation="",
                security_strategy=security_strategy,
                expected_effect="Patch applied as reviewed by developer",
            )

        review = approval_service.build_review(
            vulnerability_id=vulnerability_id,
            patch_id=patch_id,
            patch_candidate=patch_candidate,
            original_code=original_code,
            vulnerability_type=vulnerability_type,
            vulnerability_description=vulnerability_description,
            vulnerability_severity=vulnerability_severity,
            safety_threshold=safety_threshold,
            historical_success_rate=historical_success_rate,
        )
        return review
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Review assembly failed",
        )


@router.post(
    "/{vulnerability_id}/patches/{patch_id}/approve",
    response_model=PatchApprovalResponse,
    status_code=status.HTTP_200_OK,
)
async def approve_patch_endpoint(
    vulnerability_id: str,
    patch_id: str,
    request: ApprovePatchRequest,
    http_request: Request = None,
):
    """
    Record developer approval of a patch.

    Stores:
    - Developer ID
    - Timestamp
    - Confidence score at time of approval
    - Vulnerability type
    - Patch strategy

    IMPORTANT: This does NOT deploy the patch.
    Deployment must be handled separately with explicit deployment action.
    """
    require_api_key(http_request)
    if request.vulnerability_id != vulnerability_id:
        request.vulnerability_id = vulnerability_id
    if request.patch_id != patch_id:
        request.patch_id = patch_id

    try:
        response = approval_service.approve_patch(request)

        # Store in database
        try:
            import asyncio
            record_dict = response.approval_record.model_dump()
            try:
                loop = asyncio.get_running_loop()
                asyncio.ensure_future(
                    store_approval_record(record_dict)
                )
            except RuntimeError:
                asyncio.run(store_approval_record(record_dict))
        except Exception:
            pass

        return response
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Approval recording failed",
    )


@router.post(
    "/{vulnerability_id}/patches/{patch_id}/reject",
    response_model=PatchApprovalResponse,
    status_code=status.HTTP_200_OK,
)
async def reject_patch_endpoint(
    vulnerability_id: str,
    patch_id: str,
    request: RejectPatchRequest,
    http_request: Request = None,
):
    """
    Record developer rejection of a patch.

    Stores:
    - Developer ID
    - Timestamp
    - Optional rejection reason

    Developer can provide a reason explaining why the patch was rejected.
    """
    require_api_key(http_request)
    if request.vulnerability_id != vulnerability_id:
        request.vulnerability_id = vulnerability_id
    if request.patch_id != patch_id:
        request.patch_id = patch_id

    try:
        response = approval_service.reject_patch(request)

        # Store in database
        try:
            import asyncio
            record_dict = response.approval_record.model_dump()
            try:
                loop = asyncio.get_running_loop()
                asyncio.ensure_future(
                    store_approval_record(record_dict)
                )
            except RuntimeError:
                asyncio.run(store_approval_record(record_dict))
        except Exception:
            pass

        return response
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Rejection recording failed",
        )


@router.get(
    "/{vulnerability_id}/patches/{patch_id}/approval-status",
    status_code=status.HTTP_200_OK,
)
async def get_approval_status_endpoint(
    vulnerability_id: str,
    patch_id: str,
):
    """
    Get current approval status for a specific patch.

    Returns the approval record if one exists, or null if no decision made.
    """
    record = approval_service.get_approval_status(vulnerability_id, patch_id)
    if record:
        return {
            "vulnerability_id": vulnerability_id,
            "patch_id": patch_id,
            "record": record.model_dump(),
            "status": "success",
        }
    return {
        "vulnerability_id": vulnerability_id,
        "patch_id": patch_id,
        "record": None,
        "status": "no_decision",
    }


@router.get(
    "/{vulnerability_id}/approvals",
    status_code=status.HTTP_200_OK,
)
async def get_approvals_for_vulnerability_endpoint(
    vulnerability_id: str,
    developer_id: str = Query(default=None, description="Filter by developer"),
):
    """
    Get all approval/rejection records for a vulnerability.

    Optionally filter by developer_id.
    """
    records = approval_service.get_approval_history(
        vulnerability_id=vulnerability_id,
        developer_id=developer_id,
    )
    return {
        "vulnerability_id": vulnerability_id,
        "approvals": [r.model_dump() for r in records],
        "total": len(records),
        "status": "success",
    }


# Helper to import database storage
async def store_approval_record(record_dict: dict):
    """Store approval record in database."""
    try:
        from app.agents.database import store_patch_approval
        await store_patch_approval(record_dict)
    except Exception:
        pass
