"""
Human-in-the-Loop Patch Approval Service for HalluciShield AI.

Manages the developer review workflow for patches:
- Review: Show original code, patched code, diff, vulnerability, validation, confidence, explanation
- Accept: Record developer feedback, timestamp, confidence, vulnerability type, patch strategy
- Reject: Record rejection with optional reason

Design principles:
1. Never automatically deploy a generated patch
2. Developer approval is mandatory before any deployment
3. All decisions are recorded with full audit trail
4. Deterministic review assembly from stored data
"""

import difflib
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.agents.confidence_engine import ConfidenceEngine
from app.agents.explanation_generator import ExplanationGenerator
from app.agents.models import (
    ApprovalDecision,
    ApprovePatchRequest,
    ConfidenceResult,
    PatchApprovalRecord,
    PatchApprovalResponse,
    PatchCandidate,
    PatchExplanation,
    PatchRankEntry,
    PatchRecommendation,
    PatchReviewResponse,
    PatchValidationResult,
    RejectPatchRequest,
    RankPatchesRequest,
    RecommendationResponse,
    ValidationStatus,
)
from app.agents.patch_ranker import PatchRanker

logger = logging.getLogger(__name__)


def _generate_diff(original: str, patched: str) -> str:
    """Generate a unified diff between original and patched code."""
    original_lines = original.splitlines(keepends=True)
    patched_lines = patched.splitlines(keepends=True)
    diff = difflib.unified_diff(
        original_lines,
        patched_lines,
        fromfile="original",
        tofile="patched",
        lineterm="",
    )
    return "".join(diff)


class PatchApprovalService:
    """
    Manages human-in-the-loop patch approval workflow.

    Assembles review context from stored data, records approvals/rejections,
    and provides history of all decisions. Never auto-deploys patches.
    """

    def __init__(self):
        self.ranker = PatchRanker()
        self.explanation_generator = ExplanationGenerator()
        self.engine = ConfidenceEngine()
        self._approval_records: Dict[str, PatchApprovalRecord] = {}
        self._approval_history: List[PatchApprovalRecord] = []

    def build_review(
        self,
        vulnerability_id: str,
        patch_id: str,
        patch_candidate: Optional[PatchCandidate] = None,
        original_code: str = "",
        validation_result: Optional[PatchValidationResult] = None,
        vulnerability_type: str = "",
        vulnerability_description: str = "",
        vulnerability_severity: str = "",
        safety_threshold: float = 50.0,
        historical_success_rate: float = 0.5,
    ) -> PatchReviewResponse:
        """
        Assemble full review context for a patch before developer decision.

        Shows: original code, patched code, diff, vulnerability info,
        validation results, confidence score, and explanation.
        """
        patched_code = patch_candidate.modified_code if patch_candidate else ""
        diff = _generate_diff(original_code, patched_code) if original_code and patched_code else ""
        security_strategy = patch_candidate.security_strategy if patch_candidate else ""

        # Calculate confidence if validation result provided
        confidence_score = 0.0
        if validation_result:
            cr = self.engine.calculate_confidence(
                validation_result, historical_success_rate=historical_success_rate
            )
            confidence_score = cr.confidence_score

        # Generate explanation if validation result provided
        explanation = None
        if validation_result:
            explanation = self.explanation_generator.generate_explanation(
                validation_result,
                vulnerability_id=vulnerability_id,
                safety_threshold=safety_threshold,
                historical_success_rate=historical_success_rate,
            )

        return PatchReviewResponse(
            vulnerability_id=vulnerability_id,
            patch_id=patch_id,
            original_code=original_code,
            patched_code=patched_code,
            diff=diff,
            vulnerability_type=vulnerability_type,
            vulnerability_description=vulnerability_description,
            vulnerability_severity=vulnerability_severity,
            validation_results=validation_result,
            confidence_score=confidence_score,
            explanation=explanation,
            security_strategy=security_strategy,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    def approve_patch(
        self,
        request: ApprovePatchRequest,
    ) -> PatchApprovalResponse:
        """
        Record developer approval of a patch.

        Stores:
        - developer_id
        - timestamp
        - confidence_score at time of approval
        - vulnerability_type
        - patch_strategy
        """
        if not request.developer_id or not request.developer_id.strip():
            raise ValueError("developer_id is required and must not be empty")
        record_id = f"appr-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()

        record = PatchApprovalRecord(
            id=record_id,
            vulnerability_id=request.vulnerability_id,
            patch_id=request.patch_id,
            decision=ApprovalDecision.APPROVED,
            developer_id=request.developer_id,
            confidence_score=request.confidence_score,
            vulnerability_type=request.vulnerability_type,
            patch_strategy=request.patch_strategy,
            approved_at=now,
            created_at=now,
        )

        self._approval_records[f"{request.vulnerability_id}:{request.patch_id}"] = record
        self._approval_history.append(record)

        logger.info(
            f"[PatchApproval] Patch {request.patch_id} APPROVED by {request.developer_id} "
            f"for vulnerability {request.vulnerability_id} "
            f"(confidence: {request.confidence_score:.1f}%)"
        )

        return PatchApprovalResponse(
            vulnerability_id=request.vulnerability_id,
            patch_id=request.patch_id,
            decision=ApprovalDecision.APPROVED,
            approval_record=record,
            message=f"Patch {request.patch_id} approved by {request.developer_id}. Ready for deployment.",
            status="success",
        )

    def reject_patch(
        self,
        request: RejectPatchRequest,
    ) -> PatchApprovalResponse:
        """
        Record developer rejection of a patch.

        Stores:
        - developer_id
        - timestamp
        - optional rejection reason
        """
        if not request.developer_id or not request.developer_id.strip():
            raise ValueError("developer_id is required and must not be empty")
        record_id = f"rej-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()

        record = PatchApprovalRecord(
            id=record_id,
            vulnerability_id=request.vulnerability_id,
            patch_id=request.patch_id,
            decision=ApprovalDecision.REJECTED,
            developer_id=request.developer_id,
            rejection_reason=request.reason,
            rejected_at=now,
            created_at=now,
        )

        self._approval_records[f"{request.vulnerability_id}:{request.patch_id}"] = record
        self._approval_history.append(record)

        logger.info(
            f"[PatchApproval] Patch {request.patch_id} REJECTED by {request.developer_id} "
            f"for vulnerability {request.vulnerability_id}"
            + (f" (reason: {request.reason})" if request.reason else "")
        )

        return PatchApprovalResponse(
            vulnerability_id=request.vulnerability_id,
            patch_id=request.patch_id,
            decision=ApprovalDecision.REJECTED,
            approval_record=record,
            message=f"Patch {request.patch_id} rejected by {request.developer_id}.",
            status="success",
        )

    def get_approval_status(
        self,
        vulnerability_id: str,
        patch_id: str,
    ) -> Optional[PatchApprovalRecord]:
        """Get the current approval status for a specific patch."""
        return self._approval_records.get(f"{vulnerability_id}:{patch_id}")

    def get_approval_history(
        self,
        vulnerability_id: Optional[str] = None,
        developer_id: Optional[str] = None,
    ) -> List[PatchApprovalRecord]:
        """
        Get approval history, optionally filtered by vulnerability or developer.
        """
        records = self._approval_history

        if vulnerability_id:
            records = [r for r in records if r.vulnerability_id == vulnerability_id]
        if developer_id:
            records = [r for r in records if r.developer_id == developer_id]

        return records

    def is_patch_approved(
        self,
        vulnerability_id: str,
        patch_id: str,
    ) -> bool:
        """Check if a specific patch has been approved."""
        record = self.get_approval_status(vulnerability_id, patch_id)
        return record is not None and record.decision == ApprovalDecision.APPROVED
