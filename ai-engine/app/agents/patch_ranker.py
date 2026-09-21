"""
Patch Ranking & Recommendation Service for HalluciShield AI.

Takes validated patches and ranks them using the Adaptive Confidence Engine.
Recommends the highest-confidence patch only when it meets minimum safety criteria.

Design principles:
1. Never force a recommendation when no patch meets safety threshold
2. Display rank, confidence, validation status, and reasoning for each patch
3. Deterministic and reproducible
"""

import logging
import time
from datetime import datetime, timezone
from typing import List, Optional

from app.agents.confidence_engine import ConfidenceEngine
from app.agents.models import (
    ConfidenceResult,
    PatchRankEntry,
    PatchRecommendation,
    PatchValidationResult,
    RecommendationResponse,
    RankPatchesRequest,
    RankPatchesResponse,
    ValidationStatus,
    WeightConfig,
)

logger = logging.getLogger(__name__)

# Minimum confidence score (0-100) to recommend a patch
PATCH_SAFETY_THRESHOLD = 50.0

# Label mapping for recommendation levels
_RECOMMENDATION_LABELS = {
    "HIGH": "HIGHLY RECOMMENDED",
    "GOOD": "RECOMMENDED",
    "CONDITIONAL": "CONDITIONAL",
    "LOW": "NOT RECOMMENDED",
    "REJECT": "REJECT",
}


def _recommendation_label(score: float) -> str:
    """Map a confidence score to a human-readable label."""
    if score >= 90:
        return _RECOMMENDATION_LABELS["HIGH"]
    elif score >= 75:
        return _RECOMMENDATION_LABELS["GOOD"]
    elif score >= 50:
        return _RECOMMENDATION_LABELS["CONDITIONAL"]
    elif score >= 25:
        return _RECOMMENDATION_LABELS["LOW"]
    else:
        return _RECOMMENDATION_LABELS["REJECT"]


def _build_reasoning(cr: ConfidenceResult) -> str:
    """Build a concise reasoning string from confidence result evidence."""
    parts = []

    # Include the recommendation from the engine
    parts.append(cr.recommendation)

    # Add key positive evidence (max 3)
    positive = [e for e in cr.positive_evidence if e.startswith("[+]")]
    if positive:
        parts.append("Strengths: " + "; ".join(positive[:3]))

    # Add key negative evidence (max 2)
    negative = [e for e in cr.negative_evidence if e.startswith("[-]")]
    if negative:
        parts.append("Concerns: " + "; ".join(negative[:2]))

    # Add validation failures
    if cr.validation_failures:
        parts.append("Failures: " + "; ".join(cr.validation_failures[:2]))

    return " | ".join(parts)


def _build_patch_reasoning(cr: ConfidenceResult) -> str:
    """Build a concise reasoning string for a single patch entry."""
    parts = []

    if cr.confidence_score >= 90:
        parts.append("Strong security improvement with minimal risk.")
    elif cr.confidence_score >= 75:
        parts.append("Good security improvement. Review negative evidence.")
    elif cr.confidence_score >= 50:
        parts.append("May help but has significant concerns.")
    elif cr.confidence_score >= 25:
        parts.append("Major issues detected. Consider alternatives.")
    else:
        parts.append("Fails critical validation checks.")

    # Key positive signals
    positive = [e for e in cr.positive_evidence if e.startswith("[+]")]
    if positive:
        key_pos = []
        for e in positive:
            if any(kw in e.lower() for kw in ["compilation successful", "tests passed", "vulnerabilities found", "behavior preserved"]):
                key_pos.append(e.split(": ", 1)[-1] if ": " in e else e)
        if key_pos:
            parts.append("Key strengths: " + "; ".join(key_pos[:2]))

    # Key negative signals
    negative = [e for e in cr.negative_evidence if e.startswith("[-]")]
    if negative:
        key_neg = [e.split(": ", 1)[-1] if ": " in e else e for e in negative[:2]]
        parts.append("Concerns: " + "; ".join(key_neg))

    return " ".join(parts)


class PatchRanker:
    """
    Ranks validated patches and recommends the best one when safe.

    Uses the Adaptive Confidence Engine for deterministic scoring,
    then applies safety thresholds to decide whether to recommend.

    Optionally integrates with AdaptiveLearningEngine to use historical
    deployment success data for confidence scoring.
    """

    def __init__(
        self,
        safety_threshold: float = PATCH_SAFETY_THRESHOLD,
        weights: Optional[WeightConfig] = None,
        adaptive_learning_engine=None,
    ):
        """
        Initialize PatchRanker.

        Args:
            safety_threshold: Minimum confidence score to recommend (0-100).
            weights: Optional custom weights for the confidence engine.
            adaptive_learning_engine: Optional AdaptiveLearningEngine instance
                for querying historical success rates.
        """
        self.safety_threshold = safety_threshold
        self.engine = ConfidenceEngine(weights=weights)
        self._learning_engine = adaptive_learning_engine

    def _resolve_historical_rates(
        self,
        request: RankPatchesRequest,
    ) -> Optional[dict]:
        """
        Resolve historical success rates from learning engine or explicit request.

        Priority:
        1. Explicit historical_success_rates from request (already provided)
        2. Query AdaptiveLearningEngine using vulnerability_type + patch_strategies
        3. Default 0.5 (handled by ConfidenceEngine)
        """
        if request.historical_success_rates:
            return request.historical_success_rates

        if (
            self._learning_engine
            and request.vulnerability_type
            and request.patch_strategies
        ):
            rates = {}
            for patch_id, strategy in request.patch_strategies.items():
                rate = self._learning_engine.get_historical_weight(
                    request.vulnerability_type, strategy
                )
                rates[patch_id] = rate
                logger.info(
                    f"[PatchRanker] Historical rate for {patch_id} "
                    f"({request.vulnerability_type}/{strategy}): {rate:.4f}"
                )
            return rates

        return None

    def rank_patches(
        self,
        validation_results: List[PatchValidationResult],
        vulnerability_id: str = "",
        historical_success_rates: Optional[dict] = None,
    ) -> PatchRecommendation:
        """
        Rank validated patches and generate a recommendation.

        Args:
            validation_results: List of PatchValidationResult from ValidationAgent.
            vulnerability_id: The vulnerability ID being patched.
            historical_success_rates: Optional mapping of patch_id -> historical success rate.

        Returns:
            PatchRecommendation with ranked patches and recommendation.
        """
        start_time = time.time()

        if not validation_results:
            return PatchRecommendation(
                vulnerability_id=vulnerability_id,
                recommendation_text="No safe patch recommendation.",
                safety_threshold=self.safety_threshold,
                calculation_duration_ms=0,
                created_at=datetime.now(timezone.utc).isoformat(),
            )

        # Calculate confidence for each patch
        confidence_results: List[ConfidenceResult] = []
        for vr in validation_results:
            hist_rate = 0.5
            if historical_success_rates and vr.patch_id in historical_success_rates:
                hist_rate = historical_success_rates[vr.patch_id]

            cr = self.engine.calculate_confidence(vr, historical_success_rate=hist_rate)
            # Inject vulnerability_id if missing
            if not cr.vulnerability_id and vulnerability_id:
                cr = cr.model_copy(update={"vulnerability_id": vulnerability_id})
            confidence_results.append(cr)

        # Sort by confidence score (descending)
        confidence_results.sort(key=lambda x: x.confidence_score, reverse=True)

        # Build ranked entries
        ranked_patches: List[PatchRankEntry] = []
        for idx, cr in enumerate(confidence_results):
            meets = cr.confidence_score >= self.safety_threshold
            vr = next(
                (v for v in validation_results if v.patch_id == cr.patch_id),
                None,
            )
            sec_strategy = ""
            if vr and hasattr(vr, "security_score"):
                sec_strategy = (
                    f"Security score: {vr.security_score.score:.0%}"
                    if vr.security_score.score < 1.0
                    else "Clean security scan"
                )

            ranked_patches.append(
                PatchRankEntry(
                    rank=idx + 1,
                    patch_id=cr.patch_id,
                    security_strategy=sec_strategy,
                    validation_status=vr.validation_status.value if vr else "UNKNOWN",
                    confidence_score=cr.confidence_score,
                    recommendation_label=_recommendation_label(cr.confidence_score),
                    reasoning=_build_patch_reasoning(cr),
                    evidence=cr.positive_evidence + cr.negative_evidence,
                    meets_safety_threshold=meets,
                )
            )

        # Determine if we can recommend the top patch
        recommended_patch_id = None
        recommendation_text = "No safe patch recommendation."
        meets_safety = False

        if ranked_patches and ranked_patches[0].meets_safety_threshold:
            best = ranked_patches[0]
            recommended_patch_id = best.patch_id
            meets_safety = True
            recommendation_text = (
                f"RECOMMENDATION: Patch {best.patch_id} ({best.confidence_score:.1f}%) "
                f"- {best.recommendation_label}"
            )

        duration_ms = int((time.time() - start_time) * 1000)

        return PatchRecommendation(
            vulnerability_id=vulnerability_id,
            ranked_patches=ranked_patches,
            total_patches=len(ranked_patches),
            recommended_patch_id=recommended_patch_id,
            recommendation_text=recommendation_text,
            meets_safety_threshold=meets_safety,
            safety_threshold=self.safety_threshold,
            calculation_duration_ms=duration_ms,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    def get_recommendation(
        self,
        vulnerability_id: str,
        validation_results: List[PatchValidationResult],
        historical_success_rates: Optional[dict] = None,
    ) -> RecommendationResponse:
        """
        Get recommendation for a vulnerability.

        Returns a RecommendationResponse wrapping the PatchRecommendation.
        """
        rec = self.rank_patches(
            validation_results,
            vulnerability_id=vulnerability_id,
            historical_success_rates=historical_success_rates,
        )
        return RecommendationResponse(
            vulnerability_id=vulnerability_id,
            recommendation=rec,
            status="success",
        )
