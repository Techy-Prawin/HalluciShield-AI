"""
Adaptive Confidence Engine for HalluciShield AI.

This is the primary research contribution of HalluciShield AI.
Ranks candidate security patches using independently measured evidence.

Confidence = Σ(weight × normalized_feature)

Features:
- Static Security Improvement (25%)
- Unit Test Success (20%)
- Regression Test Success (20%)
- Compilation Success (10%)
- Performance (10%)
- Historical Success (15%)

Design principles:
1. Every feature is stored
2. Every weight is configurable
3. Calculation is deterministic
4. Final confidence score is reproducible
5. System explains why a patch received its score
6. LLM reasoning stored as evidence only, never influences score directly
7. Compilation failure or new critical vulnerabilities are heavily penalized
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

# Penalty multipliers for critical failures
COMPILATION_FAILURE_PENALTY = 0.3
CRITICAL_VULNERABILITY_PENALTY = 0.4


class ConfidenceEngine:
    """
    Adaptive Confidence Engine.

    Calculates confidence scores for candidate patches using
    deterministic weighted scoring of independent features.

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
        historical_success_rate: float = 0.5,
    ) -> ConfidenceResult:
        """
        Calculate confidence score for a single patch.

        Args:
            validation_result: PatchValidationResult from ValidationAgent
            historical_success_rate: Historical success rate for this patch type (0.0-1.0)

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

        # Apply penalties for critical failures
        features = self._apply_penalties(features, validation_result)

        # Calculate weighted score
        total_score = sum(f.weighted_score for f in features)

        # Clamp to 0-100
        confidence_score = max(0.0, min(100.0, total_score * 100.0))

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
            f"{confidence_score:.1f}% confidence"
        )

        return result

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
            hist_rate = 0.5
            if request.historical_success_rates:
                hist_rate = request.historical_success_rates.get(
                    vr.patch_id, 0.5
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

    def _apply_penalties(
        self,
        features: List[FeatureScore],
        vr: PatchValidationResult,
    ) -> List[FeatureScore]:
        """Apply penalties for critical failures."""
        # Penalty for compilation failure
        if not vr.compilation_score.success and vr.compilation_score.error:
            for f in features:
                if f.feature == FeatureName.COMPILATION_SUCCESS:
                    f.is_penalty = True
                    f.penalty_reason = f"Compilation failed: {vr.compilation_score.error}"
                    f.weighted_score *= (1.0 - COMPILATION_FAILURE_PENALTY)

        # Penalty for critical security vulnerabilities
        if vr.security_score.critical > 0:
            for f in features:
                if f.feature == FeatureName.STATIC_SECURITY:
                    f.is_penalty = True
                    f.penalty_reason = (
                        f"Introduces {vr.security_score.critical} critical "
                        f"vulnerabilit{'y' if vr.security_score.critical == 1 else 'ies'}"
                    )
                    f.weighted_score *= (1.0 - CRITICAL_VULNERABILITY_PENALTY)

        return features

    def _collect_positive_evidence(
        self,
        features: List[FeatureScore],
        vr: PatchValidationResult,
    ) -> List[str]:
        """Collect positive evidence from features."""
        evidence = []

        for f in features:
            if f.normalized_value >= 0.8 and not f.is_penalty:
                evidence.append(f"[+] {f.feature.value}: {f.evidence}")

        if vr.functional_score.behavior_preserved:
            evidence.append("[+] Functional behavior preserved")

        if vr.validation_status == ValidationStatus.PASS:
            evidence.append("[+] Validation status: PASS")

        return evidence

    def _collect_negative_evidence(
        self,
        features: List[FeatureScore],
        vr: PatchValidationResult,
    ) -> List[str]:
        """Collect negative evidence from features."""
        evidence = []

        for f in features:
            if f.is_penalty:
                evidence.append(f"[-] {f.feature.value}: {f.penalty_reason}")
            elif f.normalized_value < 0.5:
                evidence.append(f"[-] {f.feature.value}: {f.evidence}")

        if vr.security_score.high > 0:
            evidence.append(
                f"[-] High severity findings: {vr.security_score.high}"
            )

        if vr.regression_score.regressions_found > 0:
            evidence.append(
                f"[-] Regressions found: {vr.regression_score.regressions_found}"
            )

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
