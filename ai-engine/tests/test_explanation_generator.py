"""
Comprehensive test suite for Explainable Security Recommendation Generator.

Tests: models, ExplanationGenerator, checklist, feature contributions,
security comparison, API endpoint, edge cases, and determinism.
"""

import pytest
from fastapi.testclient import TestClient

from app.agents.explanation_generator import (
    ExplanationGenerator,
    _build_checklist,
    _build_feature_contributions,
    _build_security_comparison,
    _build_why_text,
)
from app.agents.models import (
    CompilationScore,
    ConfidenceResult,
    ExplanationChecklist,
    FeatureContribution,
    FeatureName,
    FeatureScore,
    FunctionalBehaviorScore,
    PatchExplanation,
    PatchRankEntry,
    PatchRecommendation,
    PatchValidationResult,
    PerformanceImpactScore,
    RankPatchesRequest,
    RegressionScore,
    SecurityFindingComparison,
    SecurityValidationScore,
    UnitTestScore,
    ValidationStatus,
    WeightConfig,
)
from app.main import app


@pytest.fixture
def generator():
    return ExplanationGenerator()


@pytest.fixture
def perfect_vr():
    return PatchValidationResult(
        patch_id="patch-A", vulnerability_id="vuln-001",
        compilation_score=CompilationScore(score=1.0, success=True, language="python"),
        unit_test_score=UnitTestScore(score=1.0, total_tests=20, passed=20, failed=0),
        regression_score=RegressionScore(score=1.0, total_tests=15, passed=15, failed=0),
        security_score=SecurityValidationScore(score=1.0, vulnerabilities_found=0),
        functional_score=FunctionalBehaviorScore(score=1.0, tests_run=20, behavior_preserved=True),
        performance_score=PerformanceImpactScore(score=1.0, within_acceptable_range=True),
        validation_status=ValidationStatus.PASS,
    )


@pytest.fixture
def failing_vr():
    return PatchValidationResult(
        patch_id="patch-B", vulnerability_id="vuln-001",
        compilation_score=CompilationScore(score=0.0, success=False, error="syntax error"),
        unit_test_score=UnitTestScore(score=0.1, total_tests=10, passed=1, failed=9),
        regression_score=RegressionScore(score=0.2, total_tests=10, passed=2, failed=8, regressions_found=8),
        security_score=SecurityValidationScore(score=0.3, vulnerabilities_found=3, critical=1, high=1, medium=1),
        functional_score=FunctionalBehaviorScore(score=0.2, tests_run=10, behavior_preserved=False),
        performance_score=PerformanceImpactScore(score=0.3, within_acceptable_range=False, time_regression_pct=120.0),
        validation_status=ValidationStatus.FAIL,
    )


@pytest.fixture
def mixed_vr():
    return PatchValidationResult(
        patch_id="patch-C", vulnerability_id="vuln-001",
        compilation_score=CompilationScore(score=1.0, success=True),
        unit_test_score=UnitTestScore(score=0.8, total_tests=20, passed=16, failed=4),
        regression_score=RegressionScore(score=1.0, total_tests=15, passed=15, failed=0),
        security_score=SecurityValidationScore(score=0.9, vulnerabilities_found=1, low=1),
        functional_score=FunctionalBehaviorScore(score=1.0, behavior_preserved=True),
        performance_score=PerformanceImpactScore(score=1.0, within_acceptable_range=True),
        validation_status=ValidationStatus.WARNING,
    )


@pytest.fixture
def security_vr():
    return PatchValidationResult(
        patch_id="patch-D", vulnerability_id="vuln-001",
        compilation_score=CompilationScore(score=1.0, success=True),
        unit_test_score=UnitTestScore(score=1.0, total_tests=10, passed=10),
        regression_score=RegressionScore(score=1.0, total_tests=10, passed=10),
        security_score=SecurityValidationScore(
            score=0.7, vulnerabilities_found=2, medium=2,
            findings=[{"type": "SQL_INJECTION"}, {"type": "XSS"}],
        ),
        functional_score=FunctionalBehaviorScore(score=1.0, behavior_preserved=True),
        performance_score=PerformanceImpactScore(score=1.0, within_acceptable_range=True),
        validation_status=ValidationStatus.WARNING,
    )


# ============================================================
# Test: Checklist Builder
# ============================================================

class TestChecklistBuilder:
    def test_perfect_checklist_all_pass(self, perfect_vr):
        cl = _build_checklist(perfect_vr)
        assert cl.compilation_passed is True
        assert cl.unit_tests_passed is True
        assert cl.regression_tests_passed is True
        assert cl.security_findings_reduced is True
        assert cl.no_critical_vulnerability is True
        assert cl.performance_acceptable is True

    def test_failing_checklist_all_fail(self, failing_vr):
        cl = _build_checklist(failing_vr)
        assert cl.compilation_passed is False
        assert cl.unit_tests_passed is False
        assert cl.regression_tests_passed is False
        assert cl.security_findings_reduced is False
        assert cl.no_critical_vulnerability is False
        assert cl.performance_acceptable is False

    def test_compilation_detail_pass(self, perfect_vr):
        cl = _build_checklist(perfect_vr)
        assert "successful" in cl.compilation_detail.lower()
        assert "python" in cl.compilation_detail.lower()

    def test_compilation_detail_fail(self, failing_vr):
        cl = _build_checklist(failing_vr)
        assert "failed" in cl.compilation_detail.lower()
        assert "syntax error" in cl.compilation_detail.lower()

    def test_unit_test_detail(self, perfect_vr):
        cl = _build_checklist(perfect_vr)
        assert "20/20" in cl.unit_tests_detail

    def test_unit_test_no_tests(self):
        vr = PatchValidationResult(
            patch_id="patch-x", vulnerability_id="vuln-001",
            compilation_score=CompilationScore(score=1.0, success=True),
            unit_test_score=UnitTestScore(score=1.0, total_tests=0, passed=0),
        )
        cl = _build_checklist(vr)
        assert "No unit tests" in cl.unit_tests_detail

    def test_regression_detail_pass(self, perfect_vr):
        cl = _build_checklist(perfect_vr)
        assert "All 15" in cl.regression_tests_detail

    def test_regression_detail_fail(self, failing_vr):
        cl = _build_checklist(failing_vr)
        assert "8 regressions" in cl.regression_tests_detail

    def test_security_detail_clean(self, perfect_vr):
        cl = _build_checklist(perfect_vr)
        assert "No vulnerabilities" in cl.security_detail

    def test_security_detail_findings(self, failing_vr):
        cl = _build_checklist(failing_vr)
        assert "3 vulnerabilities" in cl.security_detail

    def test_critical_detail_none(self, perfect_vr):
        cl = _build_checklist(perfect_vr)
        assert "No critical" in cl.critical_detail

    def test_critical_detail_present(self, failing_vr):
        cl = _build_checklist(failing_vr)
        assert "1 critical" in cl.critical_detail

    def test_performance_detail_good(self, perfect_vr):
        cl = _build_checklist(perfect_vr)
        assert "acceptable range" in cl.performance_detail.lower()

    def test_performance_detail_bad(self, failing_vr):
        cl = _build_checklist(failing_vr)
        assert "120.0%" in cl.performance_detail

    def test_checklist_is_pydantic_model(self, perfect_vr):
        cl = _build_checklist(perfect_vr)
        assert isinstance(cl, ExplanationChecklist)


# ============================================================
# Test: Feature Contributions Builder
# ============================================================

class TestFeatureContributionsBuilder:
    def test_builds_contributions(self, perfect_vr):
        cr = ConfidenceResult(
            patch_id="patch-A", confidence_score=92.5,
            feature_scores=[
                FeatureScore(feature=FeatureName.STATIC_SECURITY, raw_value=1.0, normalized_value=1.0,
                             weight=0.25, weighted_score=0.25, evidence="clean scan"),
                FeatureScore(feature=FeatureName.UNIT_TEST_SUCCESS, raw_value=1.0, normalized_value=1.0,
                             weight=0.20, weighted_score=0.20, evidence="20/20 passed"),
            ],
        )
        contribs = _build_feature_contributions(cr, 92.5)
        assert len(contribs) == 2
        assert all(isinstance(c, FeatureContribution) for c in contribs)

    def test_contributions_sorted_by_pct(self):
        cr = ConfidenceResult(
            patch_id="patch-A", confidence_score=50.0,
            feature_scores=[
                FeatureScore(feature=FeatureName.STATIC_SECURITY, raw_value=0.5, normalized_value=0.5,
                             weight=0.25, weighted_score=0.125, evidence="a"),
                FeatureScore(feature=FeatureName.UNIT_TEST_SUCCESS, raw_value=1.0, normalized_value=1.0,
                             weight=0.20, weighted_score=0.20, evidence="b"),
                FeatureScore(feature=FeatureName.COMPILATION_SUCCESS, raw_value=0.0, normalized_value=0.0,
                             weight=0.10, weighted_score=0.0, evidence="c"),
            ],
        )
        contribs = _build_feature_contributions(cr, 50.0)
        pcts = [c.contribution_pct for c in contribs]
        assert pcts == sorted(pcts, reverse=True)

    def test_passed_flag_true(self):
        cr = ConfidenceResult(
            patch_id="patch-A", confidence_score=100.0,
            feature_scores=[
                FeatureScore(feature=FeatureName.STATIC_SECURITY, raw_value=1.0, normalized_value=1.0,
                             weight=0.25, weighted_score=0.25, evidence="clean"),
            ],
        )
        contribs = _build_feature_contributions(cr, 100.0)
        assert contribs[0].passed is True

    def test_passed_flag_false_penalty(self):
        cr = ConfidenceResult(
            patch_id="patch-A", confidence_score=30.0,
            feature_scores=[
                FeatureScore(feature=FeatureName.STATIC_SECURITY, raw_value=0.2, normalized_value=0.2,
                             weight=0.25, weighted_score=0.05, evidence="bad",
                             is_penalty=True, penalty_reason="critical vuln"),
            ],
        )
        contribs = _build_feature_contributions(cr, 30.0)
        assert contribs[0].passed is False

    def test_passed_flag_false_low_score(self):
        cr = ConfidenceResult(
            patch_id="patch-A", confidence_score=30.0,
            feature_scores=[
                FeatureScore(feature=FeatureName.UNIT_TEST_SUCCESS, raw_value=0.3, normalized_value=0.3,
                             weight=0.20, weighted_score=0.06, evidence="some fail"),
            ],
        )
        contribs = _build_feature_contributions(cr, 30.0)
        assert contribs[0].passed is False

    def test_zero_total_confidence(self):
        cr = ConfidenceResult(
            patch_id="patch-A", confidence_score=0.0,
            feature_scores=[
                FeatureScore(feature=FeatureName.STATIC_SECURITY, raw_value=0.0, normalized_value=0.0,
                             weight=0.25, weighted_score=0.0, evidence="none"),
            ],
        )
        contribs = _build_feature_contributions(cr, 0.0)
        assert contribs[0].contribution_pct == 0.0


# ============================================================
# Test: Security Comparison Builder
# ============================================================

class TestSecurityComparisonBuilder:
    def test_clean_scan(self, perfect_vr):
        comps = _build_security_comparison(perfect_vr)
        assert len(comps) == 1
        assert comps[0].improved is True

    def test_findings_from_list(self, security_vr):
        comps = _build_security_comparison(security_vr)
        assert len(comps) == 2
        types = {c.finding_type for c in comps}
        assert "SQL_INJECTION" in types
        assert "XSS" in types

    def test_no_findings_no_list(self, failing_vr):
        comps = _build_security_comparison(failing_vr)
        assert len(comps) == 3

    def test_comparison_is_pydantic(self, perfect_vr):
        comps = _build_security_comparison(perfect_vr)
        assert all(isinstance(c, SecurityFindingComparison) for c in comps)


# ============================================================
# Test: Why Text Builder
# ============================================================

class TestWhyTextBuilder:
    def test_high_score_text(self):
        cr = ConfidenceResult(
            patch_id="patch-A", confidence_score=95.0, recommendation="HIGHLY RECOMMENDED",
        )
        cl = ExplanationChecklist(
            compilation_passed=True, unit_tests_passed=True, regression_tests_passed=True,
            security_findings_reduced=True, no_critical_vulnerability=True, performance_acceptable=True,
        )
        text = _build_why_text(cr, cl, 95.0)
        assert "passes" in text.lower()
        assert "95.0%" in text

    def test_low_score_text(self):
        cr = ConfidenceResult(
            patch_id="patch-A", confidence_score=15.0, recommendation="REJECT",
        )
        cl = ExplanationChecklist(
            compilation_passed=False, unit_tests_passed=False, regression_tests_passed=False,
            security_findings_reduced=False, no_critical_vulnerability=False, performance_acceptable=False,
        )
        text = _build_why_text(cr, cl, 15.0)
        assert "fails" in text.lower()
        assert "15.0%" in text

    def test_mixed_text(self):
        cr = ConfidenceResult(
            patch_id="patch-A", confidence_score=70.0, recommendation="CONDITIONAL",
        )
        cl = ExplanationChecklist(
            compilation_passed=True, unit_tests_passed=True, regression_tests_passed=True,
            security_findings_reduced=False, no_critical_vulnerability=True, performance_acceptable=True,
        )
        text = _build_why_text(cr, cl, 70.0)
        assert "passes" in text.lower()
        assert "fails" in text.lower()

    def test_deterministic(self):
        cr = ConfidenceResult(
            patch_id="patch-A", confidence_score=85.0, recommendation="RECOMMENDED",
        )
        cl = ExplanationChecklist(compilation_passed=True, unit_tests_passed=True)
        t1 = _build_why_text(cr, cl, 85.0)
        t2 = _build_why_text(cr, cl, 85.0)
        assert t1 == t2


# ============================================================
# Test: ExplanationGenerator
# ============================================================

class TestExplanationGenerator:
    def test_generate_perfect(self, generator, perfect_vr):
        exp = generator.generate_explanation(perfect_vr, vulnerability_id="vuln-001")
        assert isinstance(exp, PatchExplanation)
        assert exp.patch_id == "patch-A"
        assert exp.confidence_score >= 90.0
        assert exp.meets_safety_threshold is True

    def test_generate_failing(self, generator, failing_vr):
        exp = generator.generate_explanation(failing_vr, vulnerability_id="vuln-001")
        assert exp.confidence_score < 50.0
        assert exp.meets_safety_threshold is False

    def test_generate_mixed(self, generator, mixed_vr):
        exp = generator.generate_explanation(mixed_vr, vulnerability_id="vuln-001")
        assert 0.0 <= exp.confidence_score <= 100.0

    def test_has_checklist(self, generator, perfect_vr):
        exp = generator.generate_explanation(perfect_vr, vulnerability_id="vuln-001")
        assert isinstance(exp.checklist, ExplanationChecklist)

    def test_has_feature_contributions(self, generator, perfect_vr):
        exp = generator.generate_explanation(perfect_vr, vulnerability_id="vuln-001")
        assert len(exp.feature_contributions) == 6

    def test_has_validation_evidence(self, generator, perfect_vr):
        exp = generator.generate_explanation(perfect_vr, vulnerability_id="vuln-001")
        assert len(exp.validation_evidence) > 0

    def test_has_security_comparison(self, generator, perfect_vr):
        exp = generator.generate_explanation(perfect_vr, vulnerability_id="vuln-001")
        assert len(exp.security_comparison) >= 1

    def test_has_why_text(self, generator, perfect_vr):
        exp = generator.generate_explanation(perfect_vr, vulnerability_id="vuln-001")
        assert exp.why_this_patch != ""

    def test_has_created_at(self, generator, perfect_vr):
        exp = generator.generate_explanation(perfect_vr, vulnerability_id="vuln-001")
        assert exp.created_at != ""

    def test_vulnerability_id_set(self, generator, perfect_vr):
        exp = generator.generate_explanation(perfect_vr, vulnerability_id="vuln-001")
        assert exp.vulnerability_id == "vuln-001"

    def test_custom_threshold(self, generator, perfect_vr):
        exp = generator.generate_explanation(perfect_vr, vulnerability_id="vuln-001", safety_threshold=99.0)
        assert exp.meets_safety_threshold is False
        assert exp.safety_threshold == 99.0

    def test_deterministic(self, generator, perfect_vr):
        e1 = generator.generate_explanation(perfect_vr, vulnerability_id="vuln-001")
        e2 = generator.generate_explanation(perfect_vr, vulnerability_id="vuln-001")
        assert e1.confidence_score == e2.confidence_score
        assert e1.why_this_patch == e2.why_this_patch

    def test_feature_contributions_sum_to_score(self, generator, perfect_vr):
        exp = generator.generate_explanation(perfect_vr, vulnerability_id="vuln-001")
        total_weighted = sum(f.weighted_score for f in exp.feature_contributions)
        assert abs(total_weighted * 100.0 - exp.confidence_score) < 1.0


# ============================================================
# Test: Generate for Ranked Patch
# ============================================================

class TestRankedPatchExplanation:
    def test_uses_ranked_entry_score(self, generator, perfect_vr):
        entry = PatchRankEntry(
            rank=1, patch_id="patch-A", confidence_score=95.1,
            recommendation_label="HIGHLY RECOMMENDED",
            meets_safety_threshold=True,
        )
        exp = generator.generate_for_ranked_patch(entry, perfect_vr, vulnerability_id="vuln-001")
        assert exp.confidence_score == 95.1

    def test_uses_ranked_entry_label(self, generator, perfect_vr):
        entry = PatchRankEntry(
            rank=1, patch_id="patch-A", confidence_score=80.0,
            recommendation_label="RECOMMENDED",
            meets_safety_threshold=True,
        )
        exp = generator.generate_for_ranked_patch(entry, perfect_vr, vulnerability_id="vuln-001")
        assert exp.recommendation_label == "RECOMMENDED"


# ============================================================
# Test: Generate for Recommendation
# ============================================================

class TestRecommendationExplanation:
    def test_generates_for_all_patches(self, generator, perfect_vr, failing_vr):
        rec = PatchRecommendation(
            vulnerability_id="vuln-001",
            ranked_patches=[
                PatchRankEntry(rank=1, patch_id="patch-A", confidence_score=95.0,
                               meets_safety_threshold=True, recommendation_label="HIGHLY RECOMMENDED"),
                PatchRankEntry(rank=2, patch_id="patch-B", confidence_score=15.0,
                               meets_safety_threshold=False, recommendation_label="REJECT"),
            ],
            total_patches=2, safety_threshold=50.0,
        )
        exps = generator.generate_for_recommendation(rec, [perfect_vr, failing_vr])
        assert len(exps) == 2
        assert "patch-A" in exps
        assert "patch-B" in exps

    def test_skips_missing_vr(self, generator, perfect_vr):
        rec = PatchRecommendation(
            vulnerability_id="vuln-001",
            ranked_patches=[
                PatchRankEntry(rank=1, patch_id="patch-A", confidence_score=95.0),
                PatchRankEntry(rank=2, patch_id="patch-X", confidence_score=50.0),
            ],
            total_patches=2,
        )
        exps = generator.generate_for_recommendation(rec, [perfect_vr])
        assert "patch-A" in exps
        assert "patch-X" not in exps


# ============================================================
# Test: API Endpoint
# ============================================================

class TestExplanationEndpoint:
    def test_explanation_endpoint_success(self, perfect_vr):
        client = TestClient(app)
        data = {
            "vulnerability_id": "vuln-001",
            "validation_results": [perfect_vr.model_dump()],
        }
        resp = client.post(
            "/api/v1/vulnerabilities/vuln-001/patches/patch-A/explanation",
            json=data,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "success"
        assert body["patch_id"] == "patch-A"
        exp = body["explanation"]
        assert exp["confidence_score"] >= 90.0
        assert "checklist" in exp
        assert "feature_contributions" in exp
        assert "why_this_patch" in exp

    def test_explanation_endpoint_missing_patch(self):
        client = TestClient(app)
        vr = PatchValidationResult(
            patch_id="patch-A", vulnerability_id="vuln-001",
            compilation_score=CompilationScore(score=1.0, success=True),
            validation_status=ValidationStatus.PASS,
        )
        data = {
            "vulnerability_id": "vuln-001",
            "validation_results": [vr.model_dump()],
        }
        resp = client.post(
            "/api/v1/vulnerabilities/vuln-001/patches/patch-X/explanation",
            json=data,
        )
        assert resp.status_code == 404

    def test_explanation_endpoint_empty_list(self):
        client = TestClient(app)
        data = {"vulnerability_id": "vuln-001", "validation_results": []}
        resp = client.post(
            "/api/v1/vulnerabilities/vuln-001/patches/patch-A/explanation",
            json=data,
        )
        assert resp.status_code == 400

    def test_explanation_endpoint_response_structure(self, perfect_vr):
        client = TestClient(app)
        data = {
            "vulnerability_id": "vuln-001",
            "validation_results": [perfect_vr.model_dump()],
        }
        resp = client.post(
            "/api/v1/vulnerabilities/vuln-001/patches/patch-A/explanation",
            json=data,
        )
        body = resp.json()
        exp = body["explanation"]
        assert "vulnerability_id" in exp
        assert "patch_id" in exp
        assert "confidence_score" in exp
        assert "meets_safety_threshold" in exp
        assert "safety_threshold" in exp
        assert "why_this_patch" in exp
        assert "checklist" in exp
        assert "feature_contributions" in exp
        assert "validation_evidence" in exp
        assert "security_comparison" in exp

    def test_explanation_checklist_has_all_items(self, perfect_vr):
        client = TestClient(app)
        data = {
            "vulnerability_id": "vuln-001",
            "validation_results": [perfect_vr.model_dump()],
        }
        resp = client.post(
            "/api/v1/vulnerabilities/vuln-001/patches/patch-A/explanation",
            json=data,
        )
        cl = resp.json()["explanation"]["checklist"]
        assert "compilation_passed" in cl
        assert "unit_tests_passed" in cl
        assert "regression_tests_passed" in cl
        assert "security_findings_reduced" in cl
        assert "no_critical_vulnerability" in cl
        assert "performance_acceptable" in cl
        assert "historical_success_rate" in cl

    def test_root_includes_explanation_endpoint(self):
        client = TestClient(app)
        resp = client.get("/")
        data = resp.json()
        assert "explanationEndpoint" in data

    def test_dashboard_serves_explanation_page(self):
        client = TestClient(app)
        resp = client.get("/api/v1/dashboard/explanation")
        assert resp.status_code == 200
        assert "Explainable" in resp.text


# ============================================================
# Test: Edge Cases
# ============================================================

class TestEdgeCases:
    def test_single_feature_dominates(self, generator):
        vr = PatchValidationResult(
            patch_id="patch-A", vulnerability_id="vuln-001",
            compilation_score=CompilationScore(score=1.0, success=True),
            unit_test_score=UnitTestScore(score=1.0, total_tests=10, passed=10),
            regression_score=RegressionScore(score=1.0, total_tests=10, passed=10),
            security_score=SecurityValidationScore(score=1.0, vulnerabilities_found=0),
            functional_score=FunctionalBehaviorScore(score=1.0, behavior_preserved=True),
            performance_score=PerformanceImpactScore(score=1.0, within_acceptable_range=True),
            validation_status=ValidationStatus.PASS,
        )
        exp = generator.generate_explanation(vr, vulnerability_id="vuln-001")
        assert exp.confidence_score >= 90.0

    def test_no_vulnerabilities_in_security(self, generator):
        vr = PatchValidationResult(
            patch_id="patch-A", vulnerability_id="vuln-001",
            compilation_score=CompilationScore(score=1.0, success=True),
            unit_test_score=UnitTestScore(score=1.0, total_tests=10, passed=10),
            regression_score=RegressionScore(score=1.0, total_tests=10, passed=10),
            security_score=SecurityValidationScore(score=1.0, vulnerabilities_found=0),
            functional_score=FunctionalBehaviorScore(score=1.0, behavior_preserved=True),
            performance_score=PerformanceImpactScore(score=1.0, within_acceptable_range=True),
            validation_status=ValidationStatus.PASS,
        )
        exp = generator.generate_explanation(vr, vulnerability_id="vuln-001")
        assert exp.before_total_vulns == 0
        assert exp.after_total_vulns == 0

    def test_all_evidence_types_collected(self, generator, perfect_vr):
        exp = generator.generate_explanation(perfect_vr, vulnerability_id="vuln-001")
        has_positive = any(e.startswith("[+]") for e in exp.validation_evidence)
        assert has_positive

    def test_failing_generates_negative_evidence(self, generator, failing_vr):
        exp = generator.generate_explanation(failing_vr, vulnerability_id="vuln-001")
        has_negative = any(e.startswith("[-]") for e in exp.validation_evidence)
        has_failures = len(exp.validation_evidence) > 0
        assert has_negative or has_failures

    def test_explanation_not_inventing_results(self, generator, perfect_vr):
        exp = generator.generate_explanation(perfect_vr, vulnerability_id="vuln-001")
        for item in exp.validation_evidence:
            assert "[+]" in item or "[-]" in item or "Compilation" in item or "test" in item.lower() or "vulnerability" in item.lower()
