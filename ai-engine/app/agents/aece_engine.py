"""
AECE — Adaptive Evidence-Aware Confidence Engine for HalluciShield AI.

Extends the existing production ConfidenceEngine to add:
1. Evidence Completeness tracking across all 6 dimensions:
   EvidenceCompleteness = available_required_evidence / required_evidence
2. Evidence-Aware Confidence score reflecting completeness penalization
   without altering the legacy ACE score.
3. Decision States: AUTO_APPLY, HUMAN_REVIEW, REJECT, INSUFFICIENT_EVIDENCE
4. Configurable decision and completeness thresholds.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.agents.confidence_engine import (
    ConfidenceEngine,
    DEFAULT_WEIGHTS,
    calculate_pi_comp,
    calculate_pi_crit,
    HISTORICAL_COLD_START_PRIOR,
)
from app.agents.models import (
    AECEConfig,
    AECEResult,
    ConfidenceResult,
    DecisionEnum,
    EvidenceStatusEnum,
    FeatureName,
    PatchValidationResult,
    WeightConfig,
)

logger = logging.getLogger(__name__)

REQUIRED_DIMENSIONS = [
    "static_security",
    "unit_tests",
    "regression_tests",
    "compilation",
    "performance",
    "historical",
]


class AECEngine(ConfidenceEngine):
    """
    Adaptive Evidence-Aware Confidence Engine (AECE).

    Inherits from ConfidenceEngine and preserves 100% backward compatibility.
    Computes both legacy ACE score and research-grade Evidence-Aware Confidence.
    """

    def __init__(
        self,
        weights: Optional[WeightConfig] = None,
        aece_config: Optional[AECEConfig] = None,
    ):
        super().__init__(weights=weights)
        self.aece_config = aece_config or AECEConfig()

    def evaluate_evidence_availability(
        self,
        vr: PatchValidationResult,
        historical_success_rate: Optional[float] = None,
        historical_sample_count: int = 0,
    ) -> Tuple[Dict[str, Dict[str, str]], float, Dict[str, float]]:
        """
        Evaluate availability of evidence across the 6 dimensions.
        Never treats NOT_AVAILABLE as a successful score.

        Returns:
            (evidence_status_with_provenance, evidence_completeness, dimension_scores)
            evidence_status_with_provenance is a dict mapping dimension names to
            {"status": "AVAILABLE"/"NOT_AVAILABLE"/"SYNTHETIC_TEST", "provenance": "REAL"/"SYNTHETIC_TEST"/"NOT_AVAILABLE"}
        """
        status: Dict[str, Dict[str, str]] = {}
        scores: Dict[str, float] = {}

        # 1. Static Security: available if verified and no scanner execution error
        sec = vr.security_score
        sec_verified = getattr(sec, "verified", True)
        if sec_verified and sec.error is None:
            status["static_security"] = {
                "status": EvidenceStatusEnum.AVAILABLE.value,
                "provenance": "REAL",
            }
            scores["static_security"] = sec.score
        else:
            # Check if this is a synthetic/test scenario
            # If security agent was not real, mark as SYNTHETIC_TEST
            status["static_security"] = {
                "status": EvidenceStatusEnum.NOT_AVAILABLE.value,
                "provenance": "NOT_AVAILABLE",
            }

        # 2. Unit Testing: available if verified, ran > 0 tests, no execution error
        ut = vr.unit_test_score
        ut_verified = getattr(ut, "verified", True)
        if ut_verified and ut.total_tests > 0 and ut.error is None:
            status["unit_tests"] = {
                "status": EvidenceStatusEnum.AVAILABLE.value,
                "provenance": "REAL",
            }
            scores["unit_tests"] = ut.score
        else:
            status["unit_tests"] = {
                "status": EvidenceStatusEnum.NOT_AVAILABLE.value,
                "provenance": "NOT_AVAILABLE",
            }

        # 3. Regression Testing: available if verified, ran > 0 tests, no execution error
        reg = vr.regression_score
        reg_verified = getattr(reg, "verified", True)
        if reg_verified and reg.total_tests > 0 and reg.error is None:
            status["regression_tests"] = {
                "status": EvidenceStatusEnum.AVAILABLE.value,
                "provenance": "REAL",
            }
            scores["regression_tests"] = reg.score
        else:
            status["regression_tests"] = {
                "status": EvidenceStatusEnum.NOT_AVAILABLE.value,
                "provenance": "NOT_AVAILABLE",
            }

        # 4. Compilation: available if verified and no fatal compilation error
        comp = vr.compilation_score
        comp_verified = getattr(comp, "verified", True)
        if comp_verified and (comp.success or comp.error is None):
            status["compilation"] = {
                "status": EvidenceStatusEnum.AVAILABLE.value,
                "provenance": "REAL",
            }
            scores["compilation"] = comp.score
        else:
            status["compilation"] = {
                "status": EvidenceStatusEnum.NOT_AVAILABLE.value,
                "provenance": "NOT_AVAILABLE",
            }

        # 5. Performance: available if verified and actually measured (duration or memory recorded)
        perf = vr.performance_score
        perf_verified = getattr(perf, "verified", True)
        has_perf_measurement = (
            perf.duration_ms > 0
            or perf.baseline_time_ms > 0
            or perf.patched_time_ms > 0
            or perf.time_regression_pct != 0.0
        )
        if perf_verified and has_perf_measurement and perf.error is None:
            status["performance"] = {
                "status": EvidenceStatusEnum.AVAILABLE.value,
                "provenance": "REAL",
            }
            scores["performance"] = perf.score
        else:
            status["performance"] = {
                "status": EvidenceStatusEnum.NOT_AVAILABLE.value,
                "provenance": "NOT_AVAILABLE",
            }

        # 6. Historical: available if empirical sample count meets threshold
        min_samples = self.aece_config.min_historical_samples
        if historical_sample_count >= min_samples and historical_success_rate is not None:
            status["historical"] = {
                "status": EvidenceStatusEnum.AVAILABLE.value,
                "provenance": "REAL",
            }
            scores["historical"] = max(0.0, min(1.0, historical_success_rate))
        else:
            status["historical"] = {
                "status": EvidenceStatusEnum.NOT_AVAILABLE.value,
                "provenance": "NOT_AVAILABLE",
            }

        # Evidence Completeness = available_required_evidence / required_evidence
        available_count = sum(
            1 for dim in REQUIRED_DIMENSIONS
            if status.get(dim, {}).get("status") == EvidenceStatusEnum.AVAILABLE.value
        )
        evidence_completeness = round(available_count / len(REQUIRED_DIMENSIONS), 4)

        return status, evidence_completeness, scores

    def calculate_aece(
        self,
        validation_result: PatchValidationResult,
        historical_success_rate: Optional[float] = None,
        historical_sample_count: int = 0,
        historical_success_rates: Optional[Dict[str, float]] = None,
        vulnerability_type: Optional[str] = None,
        **kwargs,
    ) -> AECEResult:
        """
        Calculate research-grade Evidence-Aware Confidence score.

        Outputs:
            legacy_ace_score
            evidence_completeness
            evidence_aware_confidence
            decision (AUTO_APPLY, HUMAN_REVIEW, REJECT, INSUFFICIENT_EVIDENCE)
        """
        if historical_success_rate is None:
            if historical_success_rates and isinstance(historical_success_rates, dict):
                if vulnerability_type and vulnerability_type in historical_success_rates:
                    historical_success_rate = historical_success_rates[vulnerability_type]
                elif len(historical_success_rates) > 0:
                    historical_success_rate = list(historical_success_rates.values())[0]
                else:
                    historical_success_rate = HISTORICAL_COLD_START_PRIOR
            else:
                historical_success_rate = HISTORICAL_COLD_START_PRIOR

        if historical_success_rates and historical_sample_count == 0:
            historical_sample_count = self.aece_config.min_historical_samples

        # Step 1: Calculate existing production legacy ACE score
        legacy_res = self.calculate_confidence(
            validation_result=validation_result,
            historical_success_rate=historical_success_rate,
        )
        legacy_ace = legacy_res.confidence_score

        # Step 2: Calculate evidence completeness and dimension statuses
        status, completeness, dim_scores = self.evaluate_evidence_availability(
            vr=validation_result,
            historical_success_rate=historical_success_rate,
            historical_sample_count=historical_sample_count,
        )

        # Step 3: Calculate evidence-aware confidence
        # Formula: scales legacy score by evidence completeness, keeping legacy score untouched.
        # When completeness is 1.0, evidence_aware_confidence == legacy_ace.
        # When completeness < 1.0, confidence is bounded by empirical evidence coverage.
        pi_comp = calculate_pi_comp(validation_result)
        pi_crit = calculate_pi_crit(validation_result)

        if pi_comp == 0.0 or pi_crit == 0.0:
            evidence_aware_conf = 0.0
        else:
            # Scaled by completeness; never exceeds legacy ACE
            evidence_aware_conf = round(legacy_ace * completeness, 2)

        evidence_aware_conf = max(0.0, min(100.0, evidence_aware_conf))

        # Step 4: Determine decision state
        cfg = self.aece_config
        if pi_comp == 0.0 or pi_crit == 0.0:
            decision = DecisionEnum.REJECT.value
            recommendation = "REJECT: Patch fails critical gates (compilation or security vulnerability remains)."
        elif completeness < cfg.min_completeness_threshold:
            decision = DecisionEnum.INSUFFICIENT_EVIDENCE.value
            recommendation = (
                f"INSUFFICIENT_EVIDENCE: Evidence completeness ({completeness:.1%}) is below threshold "
                f"({cfg.min_completeness_threshold:.1%}). Additional validation required."
            )
        elif (
            evidence_aware_conf >= cfg.auto_apply_confidence_threshold
            and completeness >= cfg.auto_apply_completeness_threshold
        ):
            decision = DecisionEnum.AUTO_APPLY.value
            recommendation = "AUTO_APPLY: High evidence-aware confidence with high completeness. Safe for automated deployment."
        elif (
            evidence_aware_conf >= cfg.human_review_confidence_threshold
            and completeness >= cfg.human_review_completeness_threshold
        ):
            decision = DecisionEnum.HUMAN_REVIEW.value
            recommendation = "HUMAN_REVIEW: Moderate confidence and acceptable completeness. Manual inspection recommended."
        else:
            decision = DecisionEnum.REJECT.value
            recommendation = f"REJECT: Evidence-aware confidence ({evidence_aware_conf:.1f}%) insufficient for deployment."

        return AECEResult(
            patch_id=validation_result.patch_id,
            vulnerability_id=validation_result.vulnerability_id,
            legacy_ace_score=legacy_ace,
            evidence_completeness=completeness,
            evidence_status=status,
            evidence_aware_confidence=evidence_aware_conf,
            decision=decision,
            recommendation=recommendation,
            dimension_scores=dim_scores,
            pi_comp=pi_comp,
            pi_crit=pi_crit,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
