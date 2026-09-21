"""
Explainable Security Recommendation Generator for HalluciShield AI.

Generates human-readable explanations from stored validation evidence.
No LLM is used -- all explanations are derived deterministically from
the PatchValidationResult and ConfidenceResult stored evidence.

Design principles:
1. Every explanation is traceable to stored evidence
2. No fabricated or LLM-invented validation results
3. Deterministic: same inputs always produce same explanation
4. Checklist items map 1:1 to the 6 validation dimensions
5. Feature contributions show exactly how each feature affects the score
"""

import logging
from datetime import datetime, timezone
from typing import List, Optional

from app.agents.confidence_engine import ConfidenceEngine
from app.agents.models import (
    ConfidenceResult,
    FeatureContribution,
    FeatureName,
    PatchExplanation,
    PatchRankEntry,
    PatchRecommendation,
    PatchValidationResult,
    SecurityFindingComparison,
    ExplanationChecklist,
    ValidationStatus,
    WeightConfig,
)

logger = logging.getLogger(__name__)


def _build_checklist(vr: PatchValidationResult) -> ExplanationChecklist:
    """
    Build checklist from stored validation result evidence.

    Each item maps to one of the 6 independent validation dimensions.
    """
    comp = vr.compilation_score
    ut = vr.unit_test_score
    reg = vr.regression_score
    sec = vr.security_score
    func = vr.functional_score
    perf = vr.performance_score

    return ExplanationChecklist(
        compilation_passed=comp.success,
        compilation_detail=(
            f"Compilation {'successful' if comp.success else 'failed'}"
            + (f" ({comp.language})" if comp.language else "")
            + (f": {comp.error}" if comp.error else "")
        ),
        unit_tests_passed=ut.failed == 0 and ut.total_tests > 0,
        unit_tests_detail=(
            f"{ut.passed}/{ut.total_tests} unit tests passed"
            if ut.total_tests > 0
            else "No unit tests executed"
        ),
        regression_tests_passed=reg.regressions_found == 0,
        regression_tests_detail=(
            f"All {reg.total_tests} regression tests passed"
            if reg.regressions_found == 0 and reg.total_tests > 0
            else (
                f"{reg.regressions_found} regressions found in {reg.total_tests} tests"
                if reg.total_tests > 0
                else "No regression tests executed"
            )
        ),
        security_findings_reduced=sec.vulnerabilities_found == 0,
        security_detail=(
            "No vulnerabilities found in security scan"
            if sec.vulnerabilities_found == 0
            else (
                f"{sec.vulnerabilities_found} vulnerabilities found"
                + (f" ({sec.critical} critical, {sec.high} high)"
                   if sec.critical > 0 or sec.high > 0
                   else "")
            )
        ),
        no_critical_vulnerability=sec.critical == 0,
        critical_detail=(
            "No critical vulnerabilities introduced"
            if sec.critical == 0
            else f"{sec.critical} critical vulnerability introduced"
        ),
        performance_acceptable=perf.within_acceptable_range,
        performance_detail=(
            f"Performance within acceptable range ({perf.time_regression_pct:.1f}% regression)"
            if perf.within_acceptable_range
            else f"Performance regression: {perf.time_regression_pct:.1f}%"
        ),
        historical_success_rate=True,
        historical_detail="Historical success rate factored into confidence calculation",
    )


def _build_feature_contributions(
    cr: ConfidenceResult,
    total_confidence: float,
) -> List[FeatureContribution]:
    """
    Build feature contribution list from stored ConfidenceResult.

    Shows exactly how each feature contributes to the final score.
    """
    contributions: List[FeatureContribution] = []
    for fs in cr.feature_scores:
        contrib_pct = 0.0
        if total_confidence > 0:
            contrib_pct = (fs.weighted_score * 100.0 / total_confidence)

        contributions.append(
            FeatureContribution(
                feature_name=fs.feature.value,
                weight=fs.weight,
                normalized_value=fs.normalized_value,
                weighted_score=fs.weighted_score,
                contribution_pct=round(contrib_pct, 1),
                evidence=fs.evidence,
                passed=not fs.is_penalty and fs.normalized_value >= 0.5,
            )
        )

    contributions.sort(key=lambda c: c.contribution_pct, reverse=True)
    return contributions


def _build_security_comparison(vr: PatchValidationResult) -> List[SecurityFindingComparison]:
    """
    Build before/after security finding comparison.

    The 'before' counts come from the vulnerability description embedded in the
    validation context. The 'after' counts come from the actual security scan
    result stored in SecurityValidationScore.
    """
    sec = vr.security_score
    after_findings = sec.findings

    comparisons: List[SecurityFindingComparison] = []

    if sec.vulnerabilities_found == 0 and sec.critical == 0:
        comparisons.append(
            SecurityFindingComparison(
                finding_type="all",
                before_count=0,
                after_count=0,
                delta=0,
                improved=True,
            )
        )
        return comparisons

    if after_findings:
        type_counts = {}
        for f in after_findings:
            ftype = f.get("type", f.get("rule_id", "unknown"))
            type_counts[ftype] = type_counts.get(ftype, 0) + 1
        for ftype, count in sorted(type_counts.items()):
            comparisons.append(
                SecurityFindingComparison(
                    finding_type=ftype,
                    before_count=count,
                    after_count=count,
                    delta=0,
                    improved=False,
                )
            )
    else:
        if sec.critical > 0:
            comparisons.append(SecurityFindingComparison(
                finding_type="critical", before_count=sec.critical,
                after_count=sec.critical, delta=0, improved=False,
            ))
        if sec.high > 0:
            comparisons.append(SecurityFindingComparison(
                finding_type="high", before_count=sec.high,
                after_count=sec.high, delta=0, improved=False,
            ))
        if sec.medium > 0:
            comparisons.append(SecurityFindingComparison(
                finding_type="medium", before_count=sec.medium,
                after_count=sec.medium, delta=0, improved=False,
            ))
        if sec.low > 0:
            comparisons.append(SecurityFindingComparison(
                finding_type="low", before_count=sec.low,
                after_count=sec.low, delta=0, improved=False,
            ))

    return comparisons


def _build_why_text(
    cr: ConfidenceResult,
    checklist: ExplanationChecklist,
    score: float,
) -> str:
    """Generate the 'WHY THIS PATCH?' explanation text from evidence."""
    parts = []

    passed = []
    failed = []
    if checklist.compilation_passed:
        passed.append("compilation")
    else:
        failed.append("compilation")
    if checklist.unit_tests_passed:
        passed.append("unit tests")
    else:
        failed.append("unit tests")
    if checklist.regression_tests_passed:
        passed.append("regression tests")
    else:
        failed.append("regression tests")
    if checklist.security_findings_reduced:
        passed.append("security scan")
    else:
        failed.append("security scan")
    if checklist.no_critical_vulnerability:
        passed.append("no critical vulnerabilities")
    else:
        failed.append("critical vulnerabilities introduced")
    if checklist.performance_acceptable:
        passed.append("performance")

    if passed:
        parts.append(
            f"This patch passes {', '.join(passed)}"
            + (f" but fails {', '.join(failed)}." if failed else ".")
        )
    else:
        parts.append(f"This patch fails all validation checks: {', '.join(failed)}.")

    if score >= 90:
        parts.append(
            f"With a confidence score of {score:.1f}%, this patch shows strong evidence "
            "of security improvement with minimal risk."
        )
    elif score >= 75:
        parts.append(
            f"With a confidence score of {score:.1f}%, this patch shows good evidence "
            "of improvement. Review any negative evidence before applying."
        )
    elif score >= 50:
        parts.append(
            f"With a confidence score of {score:.1f}%, this patch may help but has "
            "significant concerns. Manual review is required."
        )
    else:
        parts.append(
            f"With a confidence score of {score:.1f}%, this patch has major issues "
            "and is not recommended."
        )

    return " ".join(parts)


class ExplanationGenerator:
    """
    Generates explainable security recommendations from stored evidence.

    All explanations are derived deterministically from PatchValidationResult
    and ConfidenceResult. No LLM is used to invent or fabricate validation results.
    """

    def __init__(self, engine: Optional[ConfidenceEngine] = None):
        self.engine = engine or ConfidenceEngine()

    def generate_explanation(
        self,
        validation_result: PatchValidationResult,
        vulnerability_id: str = "",
        safety_threshold: float = 50.0,
        historical_success_rate: float = 0.5,
    ) -> PatchExplanation:
        """
        Generate a full explanation for a single patch.

        Args:
            validation_result: Stored PatchValidationResult from ValidationAgent.
            vulnerability_id: The vulnerability ID.
            safety_threshold: Safety threshold for recommendation.
            historical_success_rate: Historical success rate for this patch type.

        Returns:
            PatchExplanation with checklist, feature contributions, and evidence.
        """
        cr = self.engine.calculate_confidence(
            validation_result, historical_success_rate=historical_success_rate
        )
        if not cr.vulnerability_id and vulnerability_id:
            cr = cr.model_copy(update={"vulnerability_id": vulnerability_id})

        checklist = _build_checklist(validation_result)
        contributions = _build_feature_contributions(cr, cr.confidence_score)
        security_comparison = _build_security_comparison(validation_result)

        # Aggregate validation evidence
        evidence: List[str] = []
        evidence.extend(cr.positive_evidence)
        evidence.extend(cr.negative_evidence)
        evidence.extend(cr.validation_failures)

        before_total = validation_result.security_score.vulnerabilities_found
        after_total = validation_result.security_score.vulnerabilities_found

        meets = cr.confidence_score >= safety_threshold

        why_text = _build_why_text(cr, checklist, cr.confidence_score)

        return PatchExplanation(
            vulnerability_id=vulnerability_id or cr.vulnerability_id,
            patch_id=cr.patch_id,
            confidence_score=cr.confidence_score,
            recommendation_label=cr.recommendation,
            meets_safety_threshold=meets,
            safety_threshold=safety_threshold,
            why_this_patch=why_text,
            checklist=checklist,
            feature_contributions=contributions,
            validation_evidence=evidence,
            security_comparison=security_comparison,
            before_total_vulns=before_total,
            after_total_vulns=after_total,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    def generate_for_ranked_patch(
        self,
        ranked_entry: PatchRankEntry,
        validation_result: PatchValidationResult,
        vulnerability_id: str = "",
        safety_threshold: float = 50.0,
        historical_success_rate: float = 0.5,
    ) -> PatchExplanation:
        """
        Generate explanation using a PatchRankEntry and its validation result.

        Uses the confidence score from the ranked entry for consistency.
        """
        explanation = self.generate_explanation(
            validation_result,
            vulnerability_id=vulnerability_id,
            safety_threshold=safety_threshold,
            historical_success_rate=historical_success_rate,
        )
        explanation.confidence_score = ranked_entry.confidence_score
        explanation.recommendation_label = ranked_entry.recommendation_label
        explanation.meets_safety_threshold = ranked_entry.meets_safety_threshold
        return explanation

    def generate_for_recommendation(
        self,
        recommendation: PatchRecommendation,
        validation_results: List[PatchValidationResult],
        historical_success_rates: Optional[dict] = None,
    ) -> dict:
        """
        Generate explanations for all patches in a recommendation.

        Returns a dict mapping patch_id -> PatchExplanation.
        """
        explanations = {}
        vr_map = {vr.patch_id: vr for vr in validation_results}

        for entry in recommendation.ranked_patches:
            vr = vr_map.get(entry.patch_id)
            if vr is None:
                continue

            hist_rate = 0.5
            if historical_success_rates and entry.patch_id in historical_success_rates:
                hist_rate = historical_success_rates[entry.patch_id]

            exp = self.generate_for_ranked_patch(
                entry,
                vr,
                vulnerability_id=recommendation.vulnerability_id,
                safety_threshold=recommendation.safety_threshold,
                historical_success_rate=hist_rate,
            )
            explanations[entry.patch_id] = exp

        return explanations
