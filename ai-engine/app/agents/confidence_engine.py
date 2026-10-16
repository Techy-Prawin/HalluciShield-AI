"""
Adaptive Confidence Engine for HalluciShield AI.

This is the primary research contribution of HalluciShield AI.
Ranks candidate security patches using independently measured evidence.

Production ACE Equation (from paper):
    ACE = 100 × π_comp × π_crit × (0.25 f1 + 0.20 f2 + 0.20 f3 + 0.10 f4 + 0.10 f5 + 0.15 f6)

Where:
    f1 = Static Security Evidence (post-patch security state)
    f2 = Unit Test Success (passed/total)
    f3 = Regression Test Success (independent from f2)
    f4 = Compilation Status (1.0 = compiles, 0.0 = fails, NOT_APPLICABLE for interpreted)
    f5 = Performance (within acceptable range)
    f6 = Historical Success (from Adaptive Learning engine)

    π_comp = Compilation/Completeness Gate:
        1.0 if compilation successful or NOT_APPLICABLE (interpreted language)
        0.0 if compilation fails
    
    π_crit = Critical Vulnerability Gate:
        1.0 if no critical vulnerabilities remain after patch
        0.0 if any critical vulnerability remains after patch

Design principles:
1. Every feature is stored
2. Every weight is configurable
3. Calculation is deterministic
4. Final confidence score is reproducible
5. System explains why a patch received its score
6. LLM reasoning stored as evidence only, never influences score directly
7. π_comp and π_crit are MULTIPLICATIVE GATES (not feature penalties)
8. Confidence history is stored for research experiments
"""

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from app.agents.models import (
    ConfidenceHistoryRow,
    ConfidenceRanking,
    ConfidenceResult,
    FeatureName,
    FeatureScore,
    PatchValidationResult,
    RankPatchesRequest,
    RankPatchesResponse,
    ValidationStatus,
    WeightConfig,
)

logger = logging.getLogger(__name__)

DEFAULT_WEIGHTS = WeightConfig()
ALGORITHM_VERSION = "v1.0"

# Cold-start prior for historical success when no data available
HISTORICAL_COLD_START_PRIOR = 0.5

# ============================================================
# ACE Gating Factors (Multiplicative, NOT feature penalties)
# ============================================================

def calculate_pi_comp(validation_result: PatchValidationResult) -> float:
    """
    π_comp — Compilation/Completeness Gate.
    
    Returns 1.0 if:
    - Compilation successful, OR
    - Compilation NOT_APPLICABLE (interpreted language, score=1.0, success=True, no error)
    
    Returns 0.0 if:
    - Compilation fails (success=False)
    """
    comp = validation_result.compilation_score
    if not comp.success:
        logger.info(
            f"[Confidence] π_comp = 0.0 (compilation failed: {comp.error})"
        )
        return 0.0
    # Compilation successful or not applicable (interpreted language)
    logger.info(f"[Confidence] π_comp = 1.0")
    return 1.0


def calculate_pi_crit(validation_result: PatchValidationResult) -> float:
    """
    π_crit — Critical Vulnerability Gate.
    
    Returns 1.0 if NO critical vulnerabilities remain after patch.
    Returns 0.0 if ANY critical vulnerability remains after patch.
    
    This is a HARD GATE: any critical vulnerability zeroes the ACE.
    """
    sec = validation_result.security_score
    if sec.critical > 0:
        logger.info(
            f"[Confidence] π_crit = 0.0 ({sec.critical} critical vulnerability(ies) remain)"
        )
        return 0.0
    logger.info(f"[Confidence] π_crit = 1.0")
    return 1.0


class ConfidenceEngine:
    """
    Adaptive Confidence Engine.

    Calculates confidence scores for candidate patches using
    deterministic weighted scoring of independent features.

    Implements the production ACE equation from the paper:
        ACE = 100 × π_comp × π_crit × Σ(weight_i × feature_i)

    The engine is deterministic: same inputs always produce same outputs.
    LLM reasoning is stored as supporting evidence only.
    """

    def __init__(self, weights: Optional[WeightConfig] = None):
        """
        Initialize ConfidenceEngine with optional custom weights.

        Args:
            weights: Custom WeightConfig. If None, uses defaults.
        """
        self.weights = weights or DEFAULT_WEIGHTS
        self._validate_weights()

    def _validate_weights(self):
        """Validate that weights sum to approximately 1.0."""
        total = self.weights.sum_weights()
        if abs(total - 1.0) > 0.01:
            logger.warning(
                f"[Confidence] Weights sum to {total:.4f}, expected 1.0. "
                "Scores may not be normalized."
            )

    def calculate_confidence(
        self,
        validation_result: PatchValidationResult,
        historical_success_rate: float = HISTORICAL_COLD_START_PRIOR,
    ) -> ConfidenceResult:
        """
        Calculate confidence score for a single patch.

        Args:
            validation_result: PatchValidationResult from ValidationAgent
            historical_success_rate: Historical success rate for this patch type (0.0-1.0).
                                     Defaults to cold-start prior (0.5) when no data.

        Returns:
            ConfidenceResult with score, features, evidence, and recommendation
        """
        start_time = time.time()

        logger.info(
            f"[Confidence] Calculating confidence for patch "
            f"{validation_result.patch_id}"
        )

        # Extract feature values from validation result
        features = self._extract_features(validation_result, historical_success_rate)

        # Calculate weighted sum of features (no penalties applied here)
        weighted_sum = sum(f.weighted_score for f in features)

        # Apply multiplicative gates (π_comp and π_crit)
        pi_comp = calculate_pi_comp(validation_result)
        pi_crit = calculate_pi_crit(validation_result)

        # Final ACE calculation
        ace = 100.0 * pi_comp * pi_crit * weighted_sum

        # Clamp to 0-100
        confidence_score = max(0.0, min(100.0, ace))

        # Collect evidence
        positive_evidence = self._collect_positive_evidence(features, validation_result)
        negative_evidence = self._collect_negative_evidence(features, validation_result)
        validation_failures = self._collect_validation_failures(validation_result)

        # Generate recommendation
        recommendation = self._generate_recommendation(
            confidence_score, features, validation_failures
        )

        result = ConfidenceResult(
            patch_id=validation_result.patch_id,
            vulnerability_id=validation_result.vulnerability_id,
            confidence_score=round(confidence_score, 2),
            feature_scores=features,
            weights_used=self.weights,
            positive_evidence=positive_evidence,
            negative_evidence=negative_evidence,
            validation_failures=validation_failures,
            recommendation=recommendation,
            algorithm_version=ALGORITHM_VERSION,
            calculation_duration_ms=int((time.time() - start_time) * 1000),
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        logger.info(
            f"[Confidence] Patch {validation_result.patch_id}: "
            f"ACE={confidence_score:.1f}% "
            f"(pi_comp={pi_comp}, pi_crit={pi_crit}, weighted_sum={weighted_sum:.4f})"
        )

        return result

    def calculate_aece(
        self,
        validation_result: PatchValidationResult,
        historical_success_rate: float = HISTORICAL_COLD_START_PRIOR,
        historical_sample_count: int = 0,
    ):
        """Calculate evidence-aware confidence (AECE)."""
        from app.agents.aece_engine import AECEngine
        engine = AECEngine(weights=self.weights)
        return engine.calculate_aece(
            validation_result=validation_result,
            historical_success_rate=historical_success_rate,
            historical_sample_count=historical_sample_count,
        )

    def rank_patches(
        self,
        request: RankPatchesRequest,
    ) -> RankPatchesResponse:
        """
        Rank multiple patch candidates by confidence score.

        Args:
            request: RankPatchesRequest with validation results

        Returns:
            RankPatchesResponse with ranked patches
        """
        start_time = time.time()

        logger.info(
            f"[Confidence] Ranking {len(request.validation_results)} patches "
            f"for vulnerability {request.vulnerability_id}"
        )

        # Use custom weights if provided
        if request.weights:
            self.weights = request.weights
            self._validate_weights()

        rankings = []
        for vr in request.validation_results:
            # Get historical success rate if available
            hist_rate = HISTORICAL_COLD_START_PRIOR
            if request.historical_success_rates:
                hist_rate = request.historical_success_rates.get(
                    vr.patch_id, HISTORICAL_COLD_START_PRIOR
                )

            result = self.calculate_confidence(vr, hist_rate)
            rankings.append(result)

        # Sort by confidence score (highest first)
        rankings.sort(key=lambda r: r.confidence_score, reverse=True)

        best_patch = rankings[0].patch_id if rankings else None
        worst_patch = rankings[-1].patch_id if rankings else None

        ranking = ConfidenceRanking(
            vulnerability_id=request.vulnerability_id,
            rankings=rankings,
            total_patches=len(rankings),
            best_patch_id=best_patch,
            worst_patch_id=worst_patch,
            weights_used=self.weights,
            calculation_duration_ms=int((time.time() - start_time) * 1000),
        )

        response = RankPatchesResponse(
            vulnerability_id=request.vulnerability_id,
            ranking=ranking,
            calculation_duration_ms=int((time.time() - start_time) * 1000),
        )

        logger.info(
            f"[Confidence] Ranking complete: best={best_patch} "
            f"({rankings[0].confidence_score:.1f}%), "
            f"worst={worst_patch} "
            f"({rankings[-1].confidence_score:.1f}%)"
        )

        return response

    def _extract_features(
        self,
        vr: PatchValidationResult,
        historical_success_rate: float,
    ) -> List[FeatureScore]:
        """Extract feature scores from validation result."""
        features = []

        # Feature 1: Static Security Improvement (25%)
        features.append(self._score_feature(
            FeatureName.STATIC_SECURITY,
            vr.security_score,
            self.weights.static_security,
            self._security_evidence(vr),
        ))

        # Feature 2: Unit Test Success (20%)
        features.append(self._score_feature(
            FeatureName.UNIT_TEST_SUCCESS,
            vr.unit_test_score,
            self.weights.unit_test_success,
            self._unit_test_evidence(vr),
        ))

        # Feature 3: Regression Test Success (20%)
        features.append(self._score_feature(
            FeatureName.REGRESSION_SUCCESS,
            vr.regression_score,
            self.weights.regression_success,
            self._regression_evidence(vr),
        ))

        # Feature 4: Compilation Success (10%)
        features.append(self._score_feature(
            FeatureName.COMPILATION_SUCCESS,
            vr.compilation_score,
            self.weights.compilation_success,
            self._compilation_evidence(vr),
        ))

        # Feature 5: Performance (10%)
        features.append(self._score_feature(
            FeatureName.PERFORMANCE,
            vr.performance_score,
            self.weights.performance,
            self._performance_evidence(vr),
        ))

        # Feature 6: Historical Success (15%)
        hist_score = max(0.0, min(1.0, historical_success_rate))
        features.append(FeatureScore(
            feature=FeatureName.HISTORICAL_SUCCESS,
            raw_value=hist_score,
            normalized_value=hist_score,
            weight=self.weights.historical_success,
            weighted_score=hist_score * self.weights.historical_success,
            evidence=f"Historical success rate: {hist_score:.1%}",
        ))

        return features

    def _score_feature(
        self,
        feature: FeatureName,
        score_model,
        weight: float,
        evidence: str,
    ) -> FeatureScore:
        """
        Build a FeatureScore from a dimension score model.

        Unverified dimensions (e.g., sandbox unavailable) contribute zero
        weighted score so no unmeasured evidence inflates confidence.

        NOTE: Penalties are NO LONGER applied here. The paper defines
        π_comp and π_crit as MULTIPLICATIVE GATES applied to the final
        weighted sum, not as feature-level penalties.
        """
        verified = getattr(score_model, "verified", True)
        raw = score_model.score if verified else 0.0
        if not verified:
            evidence = (
                f"{feature.value} not measured "
                f"(sandbox unavailable) - not counted"
            )
        return FeatureScore(
            feature=feature,
            raw_value=raw,
            normalized_value=raw,
            weight=weight,
            weighted_score=raw * weight,
            evidence=evidence,
        )

    def _collect_positive_evidence(
        self,
        features: List[FeatureScore],
        vr: PatchValidationResult,
    ) -> List[str]:
        """Collect positive evidence from features."""
        evidence = []

        for f in features:
            if f.normalized_value >= 0.8:
                evidence.append(f"[+] {f.feature.value}: {f.evidence}")

        if vr.functional_score.behavior_preserved:
            evidence.append("[+] Functional behavior preserved")

        if vr.validation_status == ValidationStatus.PASS:
            evidence.append("[+] Validation status: PASS")

        # Explicitly note when gates are open
        pi_comp = calculate_pi_comp(vr)
        pi_crit = calculate_pi_crit(vr)
        if pi_comp == 1.0:
            evidence.append("[+] π_comp = 1.0 (compilation gate open)")
        if pi_crit == 1.0:
            evidence.append("[+] π_crit = 1.0 (no critical vulnerabilities)")

        return evidence

    def _collect_negative_evidence(
        self,
        features: List[FeatureScore],
        vr: PatchValidationResult,
    ) -> List[str]:
        """Collect negative evidence from features."""
        evidence = []

        for f in features:
            if f.normalized_value < 0.5:
                evidence.append(f"[-] {f.feature.value}: {f.evidence}")

        if vr.security_score.high > 0:
            evidence.append(
                f"[-] High severity findings: {vr.security_score.high}"
            )

        if vr.regression_score.regressions_found > 0:
            evidence.append(
                f"[-] Regressions found: {vr.regression_score.regressions_found}"
            )

        # Explicitly note when gates are closed
        pi_comp = calculate_pi_comp(vr)
        pi_crit = calculate_pi_crit(vr)
        if pi_comp == 0.0:
            evidence.append("[-] π_comp = 0.0 (compilation failed)")
        if pi_crit == 0.0:
            evidence.append(f"[-] π_crit = 0.0 ({vr.security_score.critical} critical vulnerability(ies) remain)")

        return evidence

    def _collect_validation_failures(self, vr: PatchValidationResult) -> List[str]:
        """Collect validation failures."""
        failures = []

        if not vr.compilation_score.success:
            failures.append(
                f"Compilation failed: {vr.compilation_score.error or 'unknown error'}"
            )

        if vr.unit_test_score.failed > 0:
            failures.append(
                f"Unit tests failed: {vr.unit_test_score.failed}/{vr.unit_test_score.total_tests}"
            )

        if vr.regression_score.regressions_found > 0:
            failures.append(
                f"Regressions found: {vr.regression_score.regressions_found}"
            )

        if vr.security_score.critical > 0:
            failures.append(
                f"Critical vulnerabilities: {vr.security_score.critical}"
            )

        return failures

    def _generate_recommendation(
        self,
        confidence_score: float,
        features: List[FeatureScore],
        validation_failures: List[str],
    ) -> str:
        """Generate human-readable recommendation."""
        if confidence_score >= 90:
            return "HIGHLY RECOMMENDED: Patch shows strong evidence of security improvement with minimal risk."
        elif confidence_score >= 75:
            return "RECOMMENDED: Patch shows good security improvement. Review negative evidence before applying."
        elif confidence_score >= 50:
            return "CONDITIONAL: Patch may help but has significant concerns. Manual review required."
        elif confidence_score >= 25:
            return "NOT RECOMMENDED: Patch has major issues. Consider alternative approaches."
        else:
            return "REJECT: Patch fails critical validation checks. Do not apply."

    # ============================================================
    # Evidence helpers
    # ============================================================

    def _security_evidence(self, vr: PatchValidationResult) -> str:
        sec = vr.security_score
        if sec.vulnerabilities_found == 0:
            return "No vulnerabilities found in security scan"
        parts = [f"{sec.vulnerabilities_found} vulnerabilities found"]
        if sec.critical > 0:
            parts.append(f"{sec.critical} critical")
        if sec.high > 0:
            parts.append(f"{sec.high} high")
        return ", ".join(parts)

    def _unit_test_evidence(self, vr: PatchValidationResult) -> str:
        ut = vr.unit_test_score
        if ut.total_tests == 0:
            return "No unit tests executed"
        return f"{ut.passed}/{ut.total_tests} tests passed ({ut.score:.0%})"

    def _regression_evidence(self, vr: PatchValidationResult) -> str:
        reg = vr.regression_score
        if reg.total_tests == 0:
            return "No regression tests executed"
        if reg.regressions_found == 0:
            return f"All {reg.total_tests} regression tests passed"
        return f"{reg.regressions_found} regressions in {reg.total_tests} tests"

    def _compilation_evidence(self, vr: PatchValidationResult) -> str:
        comp = vr.compilation_score
        if comp.success:
            return f"Compilation successful ({comp.language})"
        return f"Compilation failed: {comp.error or 'unknown error'}"

    def _performance_evidence(self, vr: PatchValidationResult) -> str:
        perf = vr.performance_score
        if perf.within_acceptable_range:
            return f"Performance within acceptable range ({perf.time_regression_pct:.1f}% regression)"
        return f"Performance regression: {perf.time_regression_pct:.1f}%"


class ConfidenceService:
    """
    Service layer for confidence calculations.

    Supports alternative scoring algorithms for research experiments.
    Currently implements the default ConfidenceEngine.
    """

    def __init__(self):
        self._engines: Dict[str, ConfidenceEngine] = {}
        self._default_engine = ConfidenceEngine()

    def get_engine(self, algorithm: str = "default") -> ConfidenceEngine:
        """Get engine by algorithm name."""
        if algorithm == "default":
            return self._default_engine
        if algorithm not in self._engines:
            self._engines[algorithm] = ConfidenceEngine()
        return self._engines[algorithm]

    def register_engine(self, name: str, engine: ConfidenceEngine):
        """Register a custom engine for research experiments."""
        self._engines[name] = engine
        logger.info(f"[ConfidenceService] Registered engine: {name}")

    def calculate(
        self,
        validation_result: PatchValidationResult,
        historical_success_rate: float = 0.5,
        algorithm: str = "default",
    ) -> ConfidenceResult:
        """Calculate confidence using specified algorithm."""
        engine = self.get_engine(algorithm)
        return engine.calculate_confidence(validation_result, historical_success_rate)

    def rank(
        self,
        request: RankPatchesRequest,
        algorithm: str = "default",
    ) -> RankPatchesResponse:
        """Rank patches using specified algorithm."""
        engine = self.get_engine(algorithm)
        return engine.rank_patches(request)
