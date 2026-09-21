"""
Comprehensive test suite for Patch Ranking & Recommendation Service.

Tests: PatchRanker initialization, ranking, recommendation logic, safety threshold,
model definitions, API endpoint, edge cases, and reproducibility.
"""

import pytest
from fastapi.testclient import TestClient

from app.agents.patch_ranker import (
    PatchRanker,
    PATCH_SAFETY_THRESHOLD,
    _recommendation_label,
)
from app.agents.models import (
    CompilationScore,
    FunctionalBehaviorScore,
    PatchRankEntry,
    PatchRecommendation,
    PatchValidationResult,
    PerformanceImpactScore,
    RankPatchesRequest,
    RecommendationResponse,
    RegressionScore,
    SecurityValidationScore,
    UnitTestScore,
    ValidationStatus,
    WeightConfig,
)
from app.main import app


@pytest.fixture
def ranker():
    return PatchRanker()


@pytest.fixture
def strict_ranker():
    return PatchRanker(safety_threshold=80.0)


@pytest.fixture
def lenient_ranker():
    return PatchRanker(safety_threshold=25.0)


@pytest.fixture
def perfect_validation():
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
def good_validation():
    return PatchValidationResult(
        patch_id="patch-B", vulnerability_id="vuln-001",
        compilation_score=CompilationScore(score=1.0, success=True),
        unit_test_score=UnitTestScore(score=0.9, total_tests=20, passed=18, failed=2),
        regression_score=RegressionScore(score=1.0, total_tests=15, passed=15, failed=0),
        security_score=SecurityValidationScore(score=1.0, vulnerabilities_found=0),
        functional_score=FunctionalBehaviorScore(score=1.0, behavior_preserved=True),
        performance_score=PerformanceImpactScore(score=1.0, within_acceptable_range=True),
        validation_status=ValidationStatus.PASS,
    )


@pytest.fixture
def medium_validation():
    return PatchValidationResult(
        patch_id="patch-C", vulnerability_id="vuln-001",
        compilation_score=CompilationScore(score=1.0, success=True),
        unit_test_score=UnitTestScore(score=0.7, total_tests=20, passed=14, failed=6),
        regression_score=RegressionScore(score=0.8, total_tests=15, passed=12, failed=3, regressions_found=3),
        security_score=SecurityValidationScore(score=0.9, vulnerabilities_found=1, low=1),
        functional_score=FunctionalBehaviorScore(score=0.9, behavior_preserved=True),
        performance_score=PerformanceImpactScore(score=0.95, within_acceptable_range=True),
        validation_status=ValidationStatus.WARNING,
    )


@pytest.fixture
def poor_validation():
    return PatchValidationResult(
        patch_id="patch-D", vulnerability_id="vuln-001",
        compilation_score=CompilationScore(score=1.0, success=True),
        unit_test_score=UnitTestScore(score=0.5, total_tests=20, passed=10, failed=10),
        regression_score=RegressionScore(score=0.6, total_tests=15, passed=9, failed=6, regressions_found=6),
        security_score=SecurityValidationScore(score=0.7, vulnerabilities_found=2, medium=2),
        functional_score=FunctionalBehaviorScore(score=0.6, behavior_preserved=True),
        performance_score=PerformanceImpactScore(score=0.7, within_acceptable_range=False, time_regression_pct=40.0),
        validation_status=ValidationStatus.WARNING,
    )


@pytest.fixture
def failing_validation():
    return PatchValidationResult(
        patch_id="patch-E", vulnerability_id="vuln-001",
        compilation_score=CompilationScore(score=0.0, success=False, error="syntax error"),
        unit_test_score=UnitTestScore(score=0.1, total_tests=10, passed=1, failed=9),
        regression_score=RegressionScore(score=0.2, total_tests=10, passed=2, failed=8, regressions_found=8),
        security_score=SecurityValidationScore(score=0.3, vulnerabilities_found=3, critical=1, high=1, medium=1),
        functional_score=FunctionalBehaviorScore(score=0.2, tests_run=10, behavior_preserved=False),
        performance_score=PerformanceImpactScore(score=0.3, within_acceptable_range=False, time_regression_pct=120.0),
        validation_status=ValidationStatus.FAIL,
    )


@pytest.fixture
def five_validations(perfect_validation, good_validation, medium_validation, poor_validation, failing_validation):
    return [perfect_validation, good_validation, medium_validation, poor_validation, failing_validation]


class TestRecommendationLabel:
    def test_high_label(self):
        assert _recommendation_label(95.0) == "HIGHLY RECOMMENDED"

    def test_good_label(self):
        assert _recommendation_label(80.0) == "RECOMMENDED"

    def test_conditional_label(self):
        assert _recommendation_label(60.0) == "CONDITIONAL"

    def test_low_label(self):
        assert _recommendation_label(30.0) == "NOT RECOMMENDED"

    def test_reject_label(self):
        assert _recommendation_label(10.0) == "REJECT"

    def test_boundary_90(self):
        assert _recommendation_label(90.0) == "HIGHLY RECOMMENDED"

    def test_boundary_75(self):
        assert _recommendation_label(75.0) == "RECOMMENDED"

    def test_boundary_50(self):
        assert _recommendation_label(50.0) == "CONDITIONAL"

    def test_boundary_25(self):
        assert _recommendation_label(25.0) == "NOT RECOMMENDED"

    def test_zero(self):
        assert _recommendation_label(0.0) == "REJECT"

    def test_hundred(self):
        assert _recommendation_label(100.0) == "HIGHLY RECOMMENDED"


class TestPatchRankerInit:
    def test_default_initialization(self, ranker):
        assert ranker.safety_threshold == PATCH_SAFETY_THRESHOLD
        assert ranker.engine is not None

    def test_custom_threshold(self):
        r = PatchRanker(safety_threshold=75.0)
        assert r.safety_threshold == 75.0

    def test_zero_threshold(self):
        r = PatchRanker(safety_threshold=0.0)
        assert r.safety_threshold == 0.0

    def test_hundred_threshold(self):
        r = PatchRanker(safety_threshold=100.0)
        assert r.safety_threshold == 100.0

    def test_custom_weights_passed_to_engine(self):
        w = WeightConfig(
            static_security=0.5, unit_test_success=0.1,
            regression_success=0.1, compilation_success=0.1,
            performance=0.1, historical_success=0.1,
        )
        r = PatchRanker(weights=w)
        assert r.engine.weights.static_security == 0.5

    def test_default_safety_threshold(self):
        assert PATCH_SAFETY_THRESHOLD == 50.0


class TestRankingLogic:
    def test_ranking_returns_recommendation(self, ranker, five_validations):
        result = ranker.rank_patches(five_validations, vulnerability_id="vuln-001")
        assert isinstance(result, PatchRecommendation)

    def test_ranking_total_patches(self, ranker, five_validations):
        result = ranker.rank_patches(five_validations, vulnerability_id="vuln-001")
        assert result.total_patches == 5

    def test_ranking_sorted_by_confidence(self, ranker, five_validations):
        result = ranker.rank_patches(five_validations, vulnerability_id="vuln-001")
        scores = [p.confidence_score for p in result.ranked_patches]
        assert scores == sorted(scores, reverse=True)

    def test_rank_positions_sequential(self, ranker, five_validations):
        result = ranker.rank_patches(five_validations, vulnerability_id="vuln-001")
        ranks = [p.rank for p in result.ranked_patches]
        assert ranks == [1, 2, 3, 4, 5]

    def test_best_patch_is_rank_1(self, ranker, five_validations):
        result = ranker.rank_patches(five_validations, vulnerability_id="vuln-001")
        assert result.ranked_patches[0].patch_id == "patch-A"

    def test_worst_patch_is_last(self, ranker, five_validations):
        result = ranker.rank_patches(five_validations, vulnerability_id="vuln-001")
        assert result.ranked_patches[-1].patch_id == "patch-E"

    def test_ranking_preserves_vulnerability_id(self, ranker, five_validations):
        result = ranker.rank_patches(five_validations, vulnerability_id="vuln-001")
        assert result.vulnerability_id == "vuln-001"

    def test_ranking_has_created_at(self, ranker, five_validations):
        result = ranker.rank_patches(five_validations, vulnerability_id="vuln-001")
        assert result.created_at != ""

    def test_ranking_has_calculation_duration(self, ranker, five_validations):
        result = ranker.rank_patches(five_validations, vulnerability_id="vuln-001")
        assert result.calculation_duration_ms >= 0

    def test_all_patches_have_rank_entries(self, ranker, five_validations):
        result = ranker.rank_patches(five_validations, vulnerability_id="vuln-001")
        for entry in result.ranked_patches:
            assert isinstance(entry, PatchRankEntry)
            assert entry.rank >= 1
            assert entry.patch_id != ""
            assert 0.0 <= entry.confidence_score <= 100.0


class TestSafetyThreshold:
    def test_perfect_patch_meets_threshold(self, ranker, perfect_validation):
        result = ranker.rank_patches([perfect_validation], vulnerability_id="vuln-001")
        assert result.meets_safety_threshold is True
        assert result.recommended_patch_id == "patch-A"

    def test_perfect_patch_recommendation_text(self, ranker, perfect_validation):
        result = ranker.rank_patches([perfect_validation], vulnerability_id="vuln-001")
        assert "RECOMMENDATION" in result.recommendation_text
        assert "patch-A" in result.recommendation_text

    def test_failing_patch_does_not_meet_threshold(self, strict_ranker, failing_validation):
        result = strict_ranker.rank_patches([failing_validation], vulnerability_id="vuln-001")
        assert result.meets_safety_threshold is False
        assert result.recommended_patch_id is None
        assert "No safe patch" in result.recommendation_text

    def test_strict_threshold_no_recommendation(self, strict_ranker, five_validations):
        result = strict_ranker.rank_patches(five_validations, vulnerability_id="vuln-001")
        if result.meets_safety_threshold:
            assert result.recommended_patch_id is not None
        else:
            assert result.recommended_patch_id is None

    def test_lenient_threshold_recommends(self, lenient_ranker, medium_validation):
        result = lenient_ranker.rank_patches([medium_validation], vulnerability_id="vuln-001")
        assert result.meets_safety_threshold is True

    def test_threshold_stored_in_result(self, ranker, perfect_validation):
        result = ranker.rank_patches([perfect_validation], vulnerability_id="vuln-001")
        assert result.safety_threshold == ranker.safety_threshold

    def test_no_safe_patch_message(self, strict_ranker, failing_validation):
        result = strict_ranker.rank_patches([failing_validation], vulnerability_id="vuln-001")
        assert result.recommendation_text == "No safe patch recommendation."

    def test_mixed_patches_only_recommends_best_safe(self, ranker, perfect_validation, failing_validation):
        result = ranker.rank_patches(
            [failing_validation, perfect_validation],
            vulnerability_id="vuln-001",
        )
        assert result.recommended_patch_id == "patch-A"


class TestEmptyInputs:
    def test_empty_validations(self, ranker):
        result = ranker.rank_patches([], vulnerability_id="vuln-001")
        assert result.total_patches == 0
        assert result.ranked_patches == []
        assert result.recommended_patch_id is None
        assert "No safe patch" in result.recommendation_text

    def test_single_validation(self, ranker, perfect_validation):
        result = ranker.rank_patches([perfect_validation], vulnerability_id="vuln-001")
        assert result.total_patches == 1
        assert result.ranked_patches[0].rank == 1


class TestDeterministicReproducibility:
    def test_same_input_same_output(self, ranker, five_validations):
        result1 = ranker.rank_patches(five_validations, vulnerability_id="vuln-001")
        result2 = ranker.rank_patches(five_validations, vulnerability_id="vuln-001")
        scores1 = [p.confidence_score for p in result1.ranked_patches]
        scores2 = [p.confidence_score for p in result2.ranked_patches]
        assert scores1 == scores2

    def test_order_independent(self, ranker, five_validations):
        shuffled = list(reversed(five_validations))
        result1 = ranker.rank_patches(five_validations, vulnerability_id="vuln-001")
        result2 = ranker.rank_patches(shuffled, vulnerability_id="vuln-001")
        ids1 = [p.patch_id for p in result1.ranked_patches]
        ids2 = [p.patch_id for p in result2.ranked_patches]
        assert ids1 == ids2


class TestEntryDetails:
    def test_entry_has_security_strategy(self, ranker, perfect_validation):
        result = ranker.rank_patches([perfect_validation], vulnerability_id="vuln-001")
        entry = result.ranked_patches[0]
        assert entry.security_strategy != ""

    def test_entry_has_validation_status(self, ranker, perfect_validation):
        result = ranker.rank_patches([perfect_validation], vulnerability_id="vuln-001")
        entry = result.ranked_patches[0]
        assert entry.validation_status == "PASS"

    def test_entry_has_recommendation_label(self, ranker, perfect_validation):
        result = ranker.rank_patches([perfect_validation], vulnerability_id="vuln-001")
        entry = result.ranked_patches[0]
        assert entry.recommendation_label != ""

    def test_entry_has_reasoning(self, ranker, perfect_validation):
        result = ranker.rank_patches([perfect_validation], vulnerability_id="vuln-001")
        entry = result.ranked_patches[0]
        assert entry.reasoning != ""

    def test_entry_has_evidence(self, ranker, perfect_validation):
        result = ranker.rank_patches([perfect_validation], vulnerability_id="vuln-001")
        entry = result.ranked_patches[0]
        assert len(entry.evidence) > 0

    def test_entry_meets_threshold_flag(self, ranker, perfect_validation, failing_validation):
        result = ranker.rank_patches([perfect_validation, failing_validation], vulnerability_id="vuln-001")
        for entry in result.ranked_patches:
            if entry.confidence_score >= ranker.safety_threshold:
                assert entry.meets_safety_threshold is True
            else:
                assert entry.meets_safety_threshold is False

    def test_failing_entry_has_low_score(self, ranker, failing_validation):
        result = ranker.rank_patches([failing_validation], vulnerability_id="vuln-001")
        assert result.ranked_patches[0].confidence_score < 50.0

    def test_failing_entry_status(self, ranker, failing_validation):
        result = ranker.rank_patches([failing_validation], vulnerability_id="vuln-001")
        assert result.ranked_patches[0].validation_status == "FAIL"

    def test_failing_entry_label_is_reject(self, ranker, failing_validation):
        result = ranker.rank_patches([failing_validation], vulnerability_id="vuln-001")
        assert result.ranked_patches[0].recommendation_label == "REJECT"


class TestGetRecommendation:
    def test_returns_recommendation_response(self, ranker, five_validations):
        resp = ranker.get_recommendation("vuln-001", five_validations)
        assert isinstance(resp, RecommendationResponse)

    def test_response_has_vulnerability_id(self, ranker, five_validations):
        resp = ranker.get_recommendation("vuln-001", five_validations)
        assert resp.vulnerability_id == "vuln-001"

    def test_response_status_success(self, ranker, five_validations):
        resp = ranker.get_recommendation("vuln-001", five_validations)
        assert resp.status == "success"

    def test_response_has_recommendation(self, ranker, five_validations):
        resp = ranker.get_recommendation("vuln-001", five_validations)
        assert isinstance(resp.recommendation, PatchRecommendation)


class TestCustomThresholds:
    def test_zero_threshold_always_recommends(self):
        r = PatchRanker(safety_threshold=0.0)
        pv = PatchValidationResult(
            patch_id="patch-x", vulnerability_id="vuln-001",
            compilation_score=CompilationScore(score=0.0, success=False),
            validation_status=ValidationStatus.FAIL,
        )
        result = r.rank_patches([pv], vulnerability_id="vuln-001")
        assert result.meets_safety_threshold is True

    def test_hundred_threshold_never_recommends(self):
        r = PatchRanker(safety_threshold=100.0)
        pv = PatchValidationResult(
            patch_id="patch-x", vulnerability_id="vuln-001",
            compilation_score=CompilationScore(score=1.0, success=True),
            unit_test_score=UnitTestScore(score=1.0, total_tests=20, passed=20),
            regression_score=RegressionScore(score=1.0, total_tests=15, passed=15),
            security_score=SecurityValidationScore(score=1.0, vulnerabilities_found=0),
            functional_score=FunctionalBehaviorScore(score=1.0, behavior_preserved=True),
            performance_score=PerformanceImpactScore(score=1.0, within_acceptable_range=True),
            validation_status=ValidationStatus.PASS,
        )
        result = r.rank_patches([pv], vulnerability_id="vuln-001")
        assert result.meets_safety_threshold is False


class TestAPIEndpoint:
    def test_recommendation_endpoint_success(self, perfect_validation, good_validation):
        client = TestClient(app)
        request_data = {
            "vulnerability_id": "vuln-001",
            "validation_results": [
                perfect_validation.model_dump(),
                good_validation.model_dump(),
            ],
        }
        resp = client.post(
            "/api/v1/vulnerabilities/vuln-001/recommendation",
            json=request_data,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["vulnerability_id"] == "vuln-001"
        assert data["status"] == "success"
        assert "recommendation" in data
        assert data["recommendation"]["total_patches"] == 2

    def test_recommendation_endpoint_empty_list(self):
        client = TestClient(app)
        request_data = {
            "vulnerability_id": "vuln-001",
            "validation_results": [],
        }
        resp = client.post(
            "/api/v1/vulnerabilities/vuln-001/recommendation",
            json=request_data,
        )
        assert resp.status_code == 400

    def test_recommendation_endpoint_with_threshold(self, perfect_validation):
        client = TestClient(app)
        request_data = {
            "vulnerability_id": "vuln-001",
            "validation_results": [perfect_validation.model_dump()],
        }
        resp = client.post(
            "/api/v1/vulnerabilities/vuln-001/recommendation?safety_threshold=90.0",
            json=request_data,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["recommendation"]["safety_threshold"] == 90.0

    def test_recommendation_endpoint_returns_ranked_patches(self, perfect_validation, good_validation):
        client = TestClient(app)
        request_data = {
            "vulnerability_id": "vuln-001",
            "validation_results": [
                perfect_validation.model_dump(),
                good_validation.model_dump(),
            ],
        }
        resp = client.post(
            "/api/v1/vulnerabilities/vuln-001/recommendation",
            json=request_data,
        )
        data = resp.json()
        patches = data["recommendation"]["ranked_patches"]
        assert len(patches) == 2
        assert patches[0]["rank"] == 1
        assert patches[0]["confidence_score"] >= patches[1]["confidence_score"]

    def test_recommendation_endpoint_response_structure(self, perfect_validation):
        client = TestClient(app)
        request_data = {
            "vulnerability_id": "vuln-001",
            "validation_results": [perfect_validation.model_dump()],
        }
        resp = client.post(
            "/api/v1/vulnerabilities/vuln-001/recommendation",
            json=request_data,
        )
        data = resp.json()
        rec = data["recommendation"]
        assert "ranked_patches" in rec
        assert "recommended_patch_id" in rec
        assert "recommendation_text" in rec
        assert "meets_safety_threshold" in rec
        assert "safety_threshold" in rec

    def test_root_includes_recommendation_endpoint(self):
        client = TestClient(app)
        resp = client.get("/")
        data = resp.json()
        assert "recommendationEndpoint" in data
        assert "recommendation" in data["recommendationEndpoint"]

    def test_dashboard_serves_recommendation_page(self):
        client = TestClient(app)
        resp = client.get("/api/v1/dashboard/recommendation")
        assert resp.status_code == 200
        assert "Patch Recommendation" in resp.text
