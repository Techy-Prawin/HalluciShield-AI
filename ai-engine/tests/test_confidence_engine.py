"""
Comprehensive test suite for the Adaptive Confidence Engine.

Tests: model definitions, weight configuration, deterministic scoring,
feature extraction, penalty application, evidence collection,
recommendation generation, ranking, ConfidenceService, API endpoint,
edge cases, and reproducibility.
"""

import pytest
from app.agents.confidence_engine import (
    ConfidenceEngine,
    ConfidenceService,
    DEFAULT_WEIGHTS,
    ALGORITHM_VERSION,
    calculate_pi_comp,
    calculate_pi_crit,
    HISTORICAL_COLD_START_PRIOR,
)
from app.agents.models import (
    CompilationScore,
    ConfidenceResult,
    ConfidenceRanking,
    FeatureName,
    FeatureScore,
    FunctionalBehaviorScore,
    PatchValidationResult,
    PerformanceImpactScore,
    RankPatchesRequest,
    RankPatchesResponse,
    RegressionScore,
    SecurityValidationScore,
    UnitTestScore,
    ValidationStatus,
    WeightConfig,
)


@pytest.fixture
def engine():
    return ConfidenceEngine()


@pytest.fixture
def custom_weights():
    return WeightConfig(
        static_security=0.30, unit_test_success=0.15,
        regression_success=0.15, compilation_success=0.10,
        performance=0.10, historical_success=0.20,
    )


@pytest.fixture
def perfect_validation():
    return PatchValidationResult(
        patch_id="patch-perfect", vulnerability_id="vuln-001",
        compilation_score=CompilationScore(score=1.0, success=True, language="python"),
        unit_test_score=UnitTestScore(score=1.0, total_tests=20, passed=20, failed=0),
        regression_score=RegressionScore(score=1.0, total_tests=15, passed=15, failed=0, regressions_found=0),
        security_score=SecurityValidationScore(score=1.0, vulnerabilities_found=0),
        functional_score=FunctionalBehaviorScore(score=1.0, tests_run=20, behavior_preserved=True),
        performance_score=PerformanceImpactScore(score=1.0, within_acceptable_range=True),
        validation_status=ValidationStatus.PASS,
    )


@pytest.fixture
def failing_validation():
    return PatchValidationResult(
        patch_id="patch-failing", vulnerability_id="vuln-001",
        compilation_score=CompilationScore(score=0.0, success=False, error="syntax error"),
        unit_test_score=UnitTestScore(score=0.2, total_tests=10, passed=2, failed=8),
        regression_score=RegressionScore(score=0.3, total_tests=10, passed=7, failed=3, regressions_found=3),
        security_score=SecurityValidationScore(score=0.5, vulnerabilities_found=2, high=1, medium=1),
        functional_score=FunctionalBehaviorScore(score=0.4, tests_run=10, behavior_preserved=False),
        performance_score=PerformanceImpactScore(score=0.6, within_acceptable_range=False, time_regression_pct=60.0),
        validation_status=ValidationStatus.FAIL,
    )


@pytest.fixture
def critical_security_validation():
    return PatchValidationResult(
        patch_id="patch-critical", vulnerability_id="vuln-001",
        compilation_score=CompilationScore(score=1.0, success=True),
        unit_test_score=UnitTestScore(score=0.95, total_tests=20, passed=19, failed=1),
        regression_score=RegressionScore(score=1.0, total_tests=15, passed=15),
        security_score=SecurityValidationScore(score=0.3, vulnerabilities_found=1, critical=1),
        functional_score=FunctionalBehaviorScore(score=1.0, behavior_preserved=True),
        performance_score=PerformanceImpactScore(score=0.9, within_acceptable_range=True),
        validation_status=ValidationStatus.WARNING,
    )


@pytest.fixture
def mixed_validation():
    return PatchValidationResult(
        patch_id="patch-mixed", vulnerability_id="vuln-001",
        compilation_score=CompilationScore(score=1.0, success=True),
        unit_test_score=UnitTestScore(score=0.85, total_tests=20, passed=17, failed=3),
        regression_score=RegressionScore(score=0.9, total_tests=15, passed=14, failed=1, regressions_found=1),
        security_score=SecurityValidationScore(score=0.95, vulnerabilities_found=0),
        functional_score=FunctionalBehaviorScore(score=0.9, behavior_preserved=True),
        performance_score=PerformanceImpactScore(score=0.8, within_acceptable_range=True),
        validation_status=ValidationStatus.WARNING,
    )


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


# ============================================================
# Test: Model Definitions
# ============================================================

class TestConfidenceModels:
    def test_feature_name_enum(self):
        assert FeatureName.STATIC_SECURITY == "static_security"
        assert FeatureName.UNIT_TEST_SUCCESS == "unit_test_success"
        assert FeatureName.REGRESSION_SUCCESS == "regression_success"
        assert FeatureName.COMPILATION_SUCCESS == "compilation_success"
        assert FeatureName.PERFORMANCE == "performance"
        assert FeatureName.HISTORICAL_SUCCESS == "historical_success"

    def test_weight_config_defaults(self):
        config = WeightConfig()
        assert config.static_security == 0.25
        assert config.unit_test_success == 0.20
        assert config.regression_success == 0.20
        assert config.compilation_success == 0.10
        assert config.performance == 0.10
        assert config.historical_success == 0.15

    def test_weight_config_sum(self):
        config = WeightConfig()
        assert config.sum_weights() == pytest.approx(1.0, abs=0.001)

    def test_weight_config_custom_sum(self, custom_weights):
        assert custom_weights.sum_weights() == pytest.approx(1.0, abs=0.001)

    def test_weight_config_to_dict(self):
        config = WeightConfig()
        d = config.to_dict()
        assert isinstance(d, dict)
        assert len(d) == 6
        assert "static_security" in d

    def test_feature_score_creation(self):
        fs = FeatureScore(
            feature=FeatureName.STATIC_SECURITY, raw_value=0.9,
            normalized_value=0.9, weight=0.25, weighted_score=0.225,
            evidence="No vulnerabilities found",
        )
        assert fs.feature == FeatureName.STATIC_SECURITY
        assert fs.weighted_score == 0.225

    def test_feature_score_bounds(self):
        with pytest.raises(Exception):
            FeatureScore(
                feature=FeatureName.STATIC_SECURITY, raw_value=1.5,
                normalized_value=0.9, weight=0.25, weighted_score=0.225,
            )

    def test_confidence_result_creation(self):
        result = ConfidenceResult(patch_id="patch-1", confidence_score=85.5)
        assert result.patch_id == "patch-1"
        assert result.confidence_score == 85.5
        assert result.algorithm_version == "v1.0"

    def test_confidence_ranking_creation(self):
        ranking = ConfidenceRanking(
            vulnerability_id="vuln-001", total_patches=5,
            best_patch_id="patch-3", worst_patch_id="patch-1",
        )
        assert ranking.total_patches == 5
        assert ranking.best_patch_id == "patch-3"

    def test_rank_patches_request(self):
        request = RankPatchesRequest(vulnerability_id="vuln-001", validation_results=[])
        assert request.vulnerability_id == "vuln-001"

    def test_rank_patches_response(self):
        response = RankPatchesResponse(
            vulnerability_id="vuln-001",
            ranking=ConfidenceRanking(vulnerability_id="vuln-001"),
        )
        assert response.vulnerability_id == "vuln-001"


# ============================================================
# Test: Engine Initialization
# ============================================================

class TestEngineInitialization:
    def test_default_initialization(self, engine):
        assert engine is not None
        assert isinstance(engine, ConfidenceEngine)
        assert engine.weights == DEFAULT_WEIGHTS

    def test_custom_weights_initialization(self, custom_weights):
        engine = ConfidenceEngine(weights=custom_weights)
        assert engine.weights == custom_weights

    def test_weights_validated_on_init(self):
        weights = WeightConfig(
            static_security=0.5, unit_test_success=0.5, regression_success=0.5,
            compilation_success=0.5, performance=0.5, historical_success=0.5,
        )
        engine = ConfidenceEngine(weights=weights)
        assert engine.weights.sum_weights() == pytest.approx(3.0)


# ============================================================
# Test: Deterministic Scoring
# ============================================================

class TestDeterministicScoring:
    def test_same_input_same_output(self, engine, perfect_validation):
        result1 = engine.calculate_confidence(perfect_validation)
        result2 = engine.calculate_confidence(perfect_validation)
        assert result1.confidence_score == result2.confidence_score

    def test_perfect_score(self, engine, perfect_validation):
        result = engine.calculate_confidence(perfect_validation, historical_success_rate=1.0)
        assert result.confidence_score >= 99.0

    def test_failing_score(self, engine, failing_validation):
        result = engine.calculate_confidence(failing_validation)
        assert result.confidence_score < 50.0

    def test_score_range(self, engine, perfect_validation, failing_validation):
        for vr in [perfect_validation, failing_validation]:
            result = engine.calculate_confidence(vr)
            assert 0.0 <= result.confidence_score <= 100.0

    def test_reproducibility_across_calls(self, engine, mixed_validation):
        scores = []
        for _ in range(10):
            result = engine.calculate_confidence(mixed_validation)
            scores.append(result.confidence_score)
        assert len(set(scores)) == 1


# ============================================================
# Test: Feature Extraction
# ============================================================

class TestFeatureExtraction:
    def test_extracts_six_features(self, engine, perfect_validation):
        features = engine._extract_features(perfect_validation, 0.5)
        assert len(features) == 6

    def test_feature_names(self, engine, perfect_validation):
        features = engine._extract_features(perfect_validation, 0.5)
        feature_names = {f.feature for f in features}
        expected = {
            FeatureName.STATIC_SECURITY, FeatureName.UNIT_TEST_SUCCESS,
            FeatureName.REGRESSION_SUCCESS, FeatureName.COMPILATION_SUCCESS,
            FeatureName.PERFORMANCE, FeatureName.HISTORICAL_SUCCESS,
        }
        assert feature_names == expected

    def test_feature_weights_match_config(self, engine, perfect_validation):
        features = engine._extract_features(perfect_validation, 0.5)
        for f in features:
            expected_weight = getattr(engine.weights, f.feature.value)
            assert f.weight == pytest.approx(expected_weight)

    def test_weighted_score_calculation(self, engine, perfect_validation):
        features = engine._extract_features(perfect_validation, 0.5)
        for f in features:
            expected = f.weight * f.normalized_value
            assert f.weighted_score == pytest.approx(expected)

    def test_historical_success_rate(self, engine, perfect_validation):
        features = engine._extract_features(perfect_validation, 0.75)
        hist_feature = next(f for f in features if f.feature == FeatureName.HISTORICAL_SUCCESS)
        assert hist_feature.raw_value == 0.75
        assert hist_feature.normalized_value == 0.75

    def test_historical_success_clamped(self, engine, perfect_validation):
        features = engine._extract_features(perfect_validation, 1.5)
        hist_feature = next(f for f in features if f.feature == FeatureName.HISTORICAL_SUCCESS)
        assert hist_feature.normalized_value == 1.0

        features = engine._extract_features(perfect_validation, -0.5)
        hist_feature = next(f for f in features if f.feature == FeatureName.HISTORICAL_SUCCESS)
        assert hist_feature.normalized_value == 0.0


# ============================================================
# Test: ACE Gates (π_comp, π_crit)
# ============================================================

class TestACEGates:
    def test_pi_comp_one_when_compilation_success(self, engine, perfect_validation):
        pi_comp = calculate_pi_comp(perfect_validation)
        assert pi_comp == 1.0

    def test_pi_comp_one_when_compilation_not_applicable(self, engine):
        """Interpreted language (e.g., Python) with no compilation needed."""
        vr = PatchValidationResult(
            patch_id="p1", vulnerability_id="v1",
            compilation_score=CompilationScore(score=1.0, success=True, language="python", output="No compilation required"),
            unit_test_score=UnitTestScore(score=1.0),
            regression_score=RegressionScore(score=1.0),
            security_score=SecurityValidationScore(score=1.0),
            functional_score=FunctionalBehaviorScore(score=1.0),
            performance_score=PerformanceImpactScore(score=1.0),
        )
        pi_comp = calculate_pi_comp(vr)
        assert pi_comp == 1.0

    def test_pi_comp_zero_when_compilation_fails(self, engine, failing_validation):
        pi_comp = calculate_pi_comp(failing_validation)
        assert pi_comp == 0.0

    def test_pi_crit_one_when_no_critical_vulns(self, engine, perfect_validation):
        pi_crit = calculate_pi_crit(perfect_validation)
        assert pi_crit == 1.0

    def test_pi_crit_one_when_high_vulns_only(self, engine):
        vr = PatchValidationResult(
            patch_id="p1", vulnerability_id="v1",
            compilation_score=CompilationScore(score=1.0, success=True),
            unit_test_score=UnitTestScore(score=1.0),
            regression_score=RegressionScore(score=1.0),
            security_score=SecurityValidationScore(score=0.5, vulnerabilities_found=2, high=2),
            functional_score=FunctionalBehaviorScore(score=1.0),
            performance_score=PerformanceImpactScore(score=1.0),
        )
        pi_crit = calculate_pi_crit(vr)
        assert pi_crit == 1.0

    def test_pi_crit_zero_when_critical_vuln_remains(self, engine, critical_security_validation):
        pi_crit = calculate_pi_crit(critical_security_validation)
        assert pi_crit == 0.0

    def test_pi_crit_zero_with_multiple_critical(self, engine):
        vr = PatchValidationResult(
            patch_id="p1", vulnerability_id="v1",
            compilation_score=CompilationScore(score=1.0, success=True),
            unit_test_score=UnitTestScore(score=1.0),
            regression_score=RegressionScore(score=1.0),
            security_score=SecurityValidationScore(score=0.0, vulnerabilities_found=3, critical=3),
            functional_score=FunctionalBehaviorScore(score=1.0),
            performance_score=PerformanceImpactScore(score=1.0),
        )
        pi_crit = calculate_pi_crit(vr)
        assert pi_crit == 0.0

    def test_gate_multiplication_zeroes_ace(self, engine, critical_security_validation):
        """ACE = 100 * π_comp * π_crit * weighted_sum = 0 when π_crit = 0"""
        result = engine.calculate_confidence(critical_security_validation, historical_success_rate=1.0)
        assert result.confidence_score == 0.0

    def test_gate_compilation_zeroes_ace(self, engine, failing_validation):
        """ACE = 100 * π_comp * π_crit * weighted_sum = 0 when π_comp = 0"""
        result = engine.calculate_confidence(failing_validation, historical_success_rate=1.0)
        assert result.confidence_score == 0.0

    def test_perfect_gates_give_max_ace(self, engine, perfect_validation):
        """ACE = 100 * 1.0 * 1.0 * 1.0 = 100 when all perfect"""
        result = engine.calculate_confidence(perfect_validation, historical_success_rate=1.0)
        assert result.confidence_score == pytest.approx(100.0, abs=0.1)

    def test_gates_documented_in_evidence(self, engine, perfect_validation):
        result = engine.calculate_confidence(perfect_validation)
        # Gates should be mentioned in positive evidence
        pi_comp_evidence = any("π_comp" in e and "1.0" in e for e in result.positive_evidence)
        pi_crit_evidence = any("π_crit" in e and "1.0" in e for e in result.positive_evidence)
        assert pi_comp_evidence
        assert pi_crit_evidence

    def test_gates_documented_when_closed(self, engine, critical_security_validation):
        result = engine.calculate_confidence(critical_security_validation)
        pi_crit_evidence = any("π_crit" in e and "0.0" in e for e in result.negative_evidence)
        assert pi_crit_evidence


# ============================================================
# Test: Evidence Collection
# ============================================================

class TestEvidenceCollection:
    def test_positive_evidence_for_perfect(self, engine, perfect_validation):
        features = engine._extract_features(perfect_validation, 0.5)
        evidence = engine._collect_positive_evidence(features, perfect_validation)
        assert len(evidence) > 0
        assert any("[+]" in e for e in evidence)

    def test_negative_evidence_for_failing(self, engine, failing_validation):
        features = engine._extract_features(failing_validation, 0.5)
        evidence = engine._collect_negative_evidence(features, failing_validation)
        assert len(evidence) > 0
        assert any("[-]" in e for e in evidence)

    def test_validation_failures_collected(self, engine, failing_validation):
        failures = engine._collect_validation_failures(failing_validation)
        assert len(failures) > 0

    def test_no_failures_for_perfect(self, engine, perfect_validation):
        failures = engine._collect_validation_failures(perfect_validation)
        assert len(failures) == 0

    def test_regression_failure_in_evidence(self, engine, failing_validation):
        failures = engine._collect_validation_failures(failing_validation)
        assert any("Regressions" in f for f in failures)

    def test_security_failure_in_evidence(self, engine, critical_security_validation):
        failures = engine._collect_validation_failures(critical_security_validation)
        assert any("Critical" in f for f in failures)

    def test_gates_in_positive_evidence(self, engine, perfect_validation):
        result = engine.calculate_confidence(perfect_validation)
        assert any("π_comp = 1.0" in e for e in result.positive_evidence)
        assert any("π_crit = 1.0" in e for e in result.positive_evidence)

    def test_gates_in_negative_evidence(self, engine, critical_security_validation):
        result = engine.calculate_confidence(critical_security_validation)
        assert any("π_crit = 0.0" in e for e in result.negative_evidence)

    def test_unit_test_failure_in_evidence(self, engine, failing_validation):
        failures = engine._collect_validation_failures(failing_validation)
        assert any("Unit tests" in f for f in failures)


# ============================================================
# Test: Recommendation Generation
# ============================================================

class TestRecommendationGeneration:
    def test_high_confidence_recommendation(self, engine):
        rec = engine._generate_recommendation(95.0, [], [])
        assert "HIGHLY RECOMMENDED" in rec

    def test_good_confidence_recommendation(self, engine):
        rec = engine._generate_recommendation(80.0, [], [])
        assert "RECOMMENDED" in rec

    def test_conditional_recommendation(self, engine):
        rec = engine._generate_recommendation(60.0, [], [])
        assert "CONDITIONAL" in rec

    def test_not_recommended(self, engine):
        rec = engine._generate_recommendation(30.0, [], [])
        assert "NOT RECOMMENDED" in rec

    def test_reject_recommendation(self, engine):
        rec = engine._generate_recommendation(10.0, [], [])
        assert "REJECT" in rec

    def test_boundary_90(self, engine):
        rec = engine._generate_recommendation(90.0, [], [])
        assert "HIGHLY RECOMMENDED" in rec

    def test_boundary_75(self, engine):
        rec = engine._generate_recommendation(75.0, [], [])
        assert "RECOMMENDED" in rec

    def test_boundary_50(self, engine):
        rec = engine._generate_recommendation(50.0, [], [])
        assert "CONDITIONAL" in rec

    def test_boundary_25(self, engine):
        rec = engine._generate_recommendation(25.0, [], [])
        assert "NOT RECOMMENDED" in rec


# ============================================================
# Test: Ranking
# ============================================================

class TestRanking:
    def test_ranking_sorts_by_confidence(self, engine, perfect_validation, failing_validation, mixed_validation):
        request = RankPatchesRequest(
            vulnerability_id="vuln-001",
            validation_results=[failing_validation, perfect_validation, mixed_validation],
        )
        response = engine.rank_patches(request)
        scores = [r.confidence_score for r in response.ranking.rankings]
        assert scores == sorted(scores, reverse=True)

    def test_ranking_identifies_best_patch(self, engine, perfect_validation, failing_validation):
        request = RankPatchesRequest(
            vulnerability_id="vuln-001",
            validation_results=[failing_validation, perfect_validation],
        )
        response = engine.rank_patches(request)
        assert response.ranking.best_patch_id == "patch-perfect"

    def test_ranking_identifies_worst_patch(self, engine, perfect_validation, failing_validation):
        request = RankPatchesRequest(
            vulnerability_id="vuln-001",
            validation_results=[failing_validation, perfect_validation],
        )
        response = engine.rank_patches(request)
        assert response.ranking.worst_patch_id == "patch-failing"

    def test_ranking_total_patches(self, engine, perfect_validation, failing_validation, mixed_validation):
        request = RankPatchesRequest(
            vulnerability_id="vuln-001",
            validation_results=[perfect_validation, failing_validation, mixed_validation],
        )
        response = engine.rank_patches(request)
        assert response.ranking.total_patches == 3

    def test_ranking_with_custom_weights(self, engine, perfect_validation, failing_validation, custom_weights):
        request = RankPatchesRequest(
            vulnerability_id="vuln-001",
            validation_results=[perfect_validation, failing_validation],
            weights=custom_weights,
        )
        response = engine.rank_patches(request)
        assert response.ranking.weights_used == custom_weights

    def test_ranking_with_historical_rates(self, engine, perfect_validation):
        request = RankPatchesRequest(
            vulnerability_id="vuln-001",
            validation_results=[perfect_validation],
            historical_success_rates={"patch-perfect": 0.9},
        )
        response = engine.rank_patches(request)
        assert len(response.ranking.rankings) == 1
        hist_feature = next(
            f for f in response.ranking.rankings[0].feature_scores
            if f.feature == FeatureName.HISTORICAL_SUCCESS
        )
        assert hist_feature.raw_value == 0.9

    def test_ranking_single_patch(self, engine, perfect_validation):
        request = RankPatchesRequest(
            vulnerability_id="vuln-001",
            validation_results=[perfect_validation],
        )
        response = engine.rank_patches(request)
        assert response.ranking.total_patches == 1
        assert response.ranking.best_patch_id == "patch-perfect"
        assert response.ranking.worst_patch_id == "patch-perfect"

    def test_ranking_preserves_vulnerability_id(self, engine, perfect_validation):
        request = RankPatchesRequest(
            vulnerability_id="vuln-xyz",
            validation_results=[perfect_validation],
        )
        response = engine.rank_patches(request)
        assert response.vulnerability_id == "vuln-xyz"
        assert response.ranking.vulnerability_id == "vuln-xyz"

    def test_ranking_result_has_algorithm_version(self, engine, perfect_validation):
        request = RankPatchesRequest(
            vulnerability_id="vuln-001",
            validation_results=[perfect_validation],
        )
        response = engine.rank_patches(request)
        for ranking in response.ranking.rankings:
            assert ranking.algorithm_version == ALGORITHM_VERSION

    def test_ranking_perfect_beats_mixed(self, engine, perfect_validation, mixed_validation):
        request = RankPatchesRequest(
            vulnerability_id="vuln-001",
            validation_results=[mixed_validation, perfect_validation],
        )
        response = engine.rank_patches(request)
        assert response.ranking.best_patch_id == "patch-perfect"


# ============================================================
# Test: ConfidenceService
# ============================================================

class TestConfidenceService:
    def test_service_initialization(self):
        service = ConfidenceService()
        assert service is not None

    def test_service_get_default_engine(self):
        service = ConfidenceService()
        engine = service.get_engine("default")
        assert isinstance(engine, ConfidenceEngine)

    def test_service_register_custom_engine(self):
        service = ConfidenceService()
        custom_engine = ConfidenceEngine(weights=WeightConfig(
            static_security=0.5, unit_test_success=0.5,
            regression_success=0.0, compilation_success=0.0,
            performance=0.0, historical_success=0.0,
        ))
        service.register_engine("experiment-1", custom_engine)
        retrieved = service.get_engine("experiment-1")
        assert retrieved == custom_engine

    def test_service_calculate(self, perfect_validation):
        service = ConfidenceService()
        result = service.calculate(perfect_validation)
        assert isinstance(result, ConfidenceResult)
        assert result.confidence_score >= 0

    def test_service_rank(self, perfect_validation, failing_validation):
        service = ConfidenceService()
        request = RankPatchesRequest(
            vulnerability_id="vuln-001",
            validation_results=[perfect_validation, failing_validation],
        )
        response = service.rank(request)
        assert isinstance(response, RankPatchesResponse)
        assert response.ranking.total_patches == 2

    def test_service_algorithms_independent(self):
        vr = PatchValidationResult(
            patch_id="patch-test",
            compilation_score=CompilationScore(score=0.9, success=True),
            unit_test_score=UnitTestScore(score=0.1),
            regression_score=RegressionScore(score=0.9),
            security_score=SecurityValidationScore(score=0.8),
            functional_score=FunctionalBehaviorScore(score=0.9),
            performance_score=PerformanceImpactScore(score=0.9),
            validation_status=ValidationStatus.PASS,
        )
        service = ConfidenceService()
        service.register_engine("exp-a", ConfidenceEngine(weights=WeightConfig(
            static_security=1.0, unit_test_success=0.0, regression_success=0.0,
            compilation_success=0.0, performance=0.0, historical_success=0.0,
        )))
        service.register_engine("exp-b", ConfidenceEngine(weights=WeightConfig(
            static_security=0.0, unit_test_success=1.0, regression_success=0.0,
            compilation_success=0.0, performance=0.0, historical_success=0.0,
        )))
        result_a = service.calculate(vr, algorithm="exp-a")
        result_b = service.calculate(vr, algorithm="exp-b")
        assert result_a.confidence_score != result_b.confidence_score


# ============================================================
# Test: Score Calculation Details
# ============================================================

class TestScoreCalculation:
    def test_weighted_sum_formula(self, engine):
        vr = PatchValidationResult(
            patch_id="patch-test",
            compilation_score=CompilationScore(score=0.8, success=True),
            unit_test_score=UnitTestScore(score=0.9),
            regression_score=RegressionScore(score=0.7),
            security_score=SecurityValidationScore(score=1.0),
            functional_score=FunctionalBehaviorScore(score=0.85),
            performance_score=PerformanceImpactScore(score=0.95),
        )
        result = engine.calculate_confidence(vr, historical_success_rate=0.6)
        w = DEFAULT_WEIGHTS
        expected = (
            w.static_security * 1.0
            + w.unit_test_success * 0.9
            + w.regression_success * 0.7
            + w.compilation_success * 0.8
            + w.performance * 0.95
            + w.historical_success * 0.6
        )
        assert result.confidence_score == pytest.approx(expected * 100.0, abs=0.1)

    def test_score_with_zero_features(self, engine):
        vr = PatchValidationResult(
            patch_id="patch-zero",
            compilation_score=CompilationScore(score=0.0, success=False),
            unit_test_score=UnitTestScore(score=0.0),
            regression_score=RegressionScore(score=0.0),
            security_score=SecurityValidationScore(score=0.0),
            functional_score=FunctionalBehaviorScore(score=0.0),
            performance_score=PerformanceImpactScore(score=0.0),
        )
        result = engine.calculate_confidence(vr, historical_success_rate=0.0)
        assert result.confidence_score == pytest.approx(0.0, abs=0.1)

    def test_score_clamped_at_100(self, engine):
        vr = PatchValidationResult(
            patch_id="patch-max",
            compilation_score=CompilationScore(score=1.0, success=True),
            unit_test_score=UnitTestScore(score=1.0),
            regression_score=RegressionScore(score=1.0),
            security_score=SecurityValidationScore(score=1.0),
            functional_score=FunctionalBehaviorScore(score=1.0),
            performance_score=PerformanceImpactScore(score=1.0),
        )
        result = engine.calculate_confidence(vr, historical_success_rate=1.0)
        assert result.confidence_score <= 100.0

    def test_feature_scores_sum_to_total(self, engine, perfect_validation):
        result = engine.calculate_confidence(perfect_validation)
        feature_sum = sum(f.weighted_score for f in result.feature_scores)
        assert feature_sum * 100 == pytest.approx(result.confidence_score, abs=0.1)

    def test_weights_used_in_result(self, engine, perfect_validation):
        result = engine.calculate_confidence(perfect_validation)
        assert result.weights_used == DEFAULT_WEIGHTS


# ============================================================
# Test: API Endpoint
# ============================================================

class TestRankingEndpoint:
    def test_rank_patches_endpoint_success(self, client):
        request_data = {
            "vulnerability_id": "vuln-001",
            "validation_results": [
                {
                    "patch_id": "patch-1",
                    "compilation_score": {"score": 1.0, "success": True},
                    "unit_test_score": {"score": 1.0, "total_tests": 10, "passed": 10},
                    "regression_score": {"score": 1.0, "total_tests": 10, "passed": 10},
                    "security_score": {"score": 1.0, "vulnerabilities_found": 0},
                    "functional_score": {"score": 1.0, "behavior_preserved": True},
                    "performance_score": {"score": 1.0, "within_acceptable_range": True},
                    "validation_status": "PASS",
                },
                {
                    "patch_id": "patch-2",
                    "compilation_score": {"score": 0.0, "success": False, "error": "fail"},
                    "unit_test_score": {"score": 0.2, "total_tests": 10, "passed": 2, "failed": 8},
                    "regression_score": {"score": 0.3, "total_tests": 10, "passed": 7, "failed": 3, "regressions_found": 3},
                    "security_score": {"score": 0.5, "vulnerabilities_found": 2, "high": 1},
                    "functional_score": {"score": 0.4, "behavior_preserved": False},
                    "performance_score": {"score": 0.6, "within_acceptable_range": False, "time_regression_pct": 60.0},
                    "validation_status": "FAIL",
                },
            ],
        }
        response = client.post("/api/v1/vulnerabilities/vuln-001/rank-patches", json=request_data)
        assert response.status_code == 200
        data = response.json()
        assert data["vulnerability_id"] == "vuln-001"
        assert data["ranking"]["total_patches"] == 2
        scores = [r["confidence_score"] for r in data["ranking"]["rankings"]]
        assert scores == sorted(scores, reverse=True)

    def test_rank_patches_endpoint_empty_list(self, client):
        request_data = {"vulnerability_id": "vuln-001", "validation_results": []}
        response = client.post("/api/v1/vulnerabilities/vuln-001/rank-patches", json=request_data)
        assert response.status_code == 400

    def test_rank_patches_endpoint_returns_features(self, client):
        request_data = {
            "vulnerability_id": "vuln-002",
            "validation_results": [{
                "patch_id": "patch-1",
                "compilation_score": {"score": 1.0, "success": True},
                "unit_test_score": {"score": 1.0, "total_tests": 5, "passed": 5},
                "regression_score": {"score": 1.0, "total_tests": 5, "passed": 5},
                "security_score": {"score": 1.0},
                "functional_score": {"score": 1.0, "behavior_preserved": True},
                "performance_score": {"score": 1.0, "within_acceptable_range": True},
                "validation_status": "PASS",
            }],
        }
        response = client.post("/api/v1/vulnerabilities/vuln-002/rank-patches", json=request_data)
        assert response.status_code == 200
        data = response.json()
        ranking = data["ranking"]["rankings"][0]
        assert "feature_scores" in ranking
        assert len(ranking["feature_scores"]) == 6
        assert "positive_evidence" in ranking
        assert "negative_evidence" in ranking
        assert "recommendation" in ranking

    def test_rank_patches_endpoint_with_custom_weights(self, client):
        request_data = {
            "vulnerability_id": "vuln-003",
            "validation_results": [{
                "patch_id": "patch-1",
                "compilation_score": {"score": 1.0, "success": True},
                "unit_test_score": {"score": 1.0},
                "regression_score": {"score": 1.0},
                "security_score": {"score": 1.0},
                "functional_score": {"score": 1.0},
                "performance_score": {"score": 1.0},
                "validation_status": "PASS",
            }],
            "weights": {
                "static_security": 0.50, "unit_test_success": 0.10,
                "regression_success": 0.10, "compilation_success": 0.10,
                "performance": 0.10, "historical_success": 0.10,
            },
        }
        response = client.post("/api/v1/vulnerabilities/vuln-003/rank-patches", json=request_data)
        assert response.status_code == 200
        data = response.json()
        assert data["ranking"]["weights_used"]["static_security"] == 0.50


# ============================================================
# Test: Edge Cases
# ============================================================

class TestEdgeCases:
    def test_single_feature_dominates_with_gates_open(self):
        """When all gates are open, a single feature with weight 1.0 gives 100% ACE."""
        weights = WeightConfig(
            static_security=1.0, unit_test_success=0.0,
            regression_success=0.0, compilation_success=0.0,
            performance=0.0, historical_success=0.0,
        )
        engine = ConfidenceEngine(weights=weights)
        vr = PatchValidationResult(
            patch_id="p1",
            compilation_score=CompilationScore(score=1.0, success=True),
            unit_test_score=UnitTestScore(score=0.0),
            regression_score=RegressionScore(score=0.0),
            security_score=SecurityValidationScore(score=1.0),
            functional_score=FunctionalBehaviorScore(score=0.0),
            performance_score=PerformanceImpactScore(score=0.0),
        )
        result = engine.calculate_confidence(vr, historical_success_rate=0.0)
        assert result.confidence_score == pytest.approx(100.0, abs=0.1)

    def test_single_feature_dominates_but_compilation_fails_gives_zero(self):
        """Even with weight 1.0 on one feature, π_comp = 0 gives ACE = 0."""
        weights = WeightConfig(
            static_security=1.0, unit_test_success=0.0,
            regression_success=0.0, compilation_success=0.0,
            performance=0.0, historical_success=0.0,
        )
        engine = ConfidenceEngine(weights=weights)
        vr = PatchValidationResult(
            patch_id="p1",
            compilation_score=CompilationScore(score=0.0, success=False),
            unit_test_score=UnitTestScore(score=0.0),
            regression_score=RegressionScore(score=0.0),
            security_score=SecurityValidationScore(score=1.0),
            functional_score=FunctionalBehaviorScore(score=0.0),
            performance_score=PerformanceImpactScore(score=0.0),
        )
        result = engine.calculate_confidence(vr, historical_success_rate=0.0)
        assert result.confidence_score == pytest.approx(0.0, abs=0.1)

    def test_all_zero_weights(self):
        weights = WeightConfig(
            static_security=0.0, unit_test_success=0.0,
            regression_success=0.0, compilation_success=0.0,
            performance=0.0, historical_success=0.0,
        )
        engine = ConfidenceEngine(weights=weights)
        vr = PatchValidationResult(
            patch_id="p1",
            compilation_score=CompilationScore(score=1.0, success=True),
            unit_test_score=UnitTestScore(score=1.0),
            regression_score=RegressionScore(score=1.0),
            security_score=SecurityValidationScore(score=1.0),
            functional_score=FunctionalBehaviorScore(score=1.0),
            performance_score=PerformanceImpactScore(score=1.0),
        )
        result = engine.calculate_confidence(vr, historical_success_rate=1.0)
        assert result.confidence_score == pytest.approx(0.0, abs=0.1)

    def test_five_candidates_ranking(self, engine):
        results = []
        for i in range(5):
            score = i / 4.0
            results.append(PatchValidationResult(
                patch_id=f"patch-{i}",
                compilation_score=CompilationScore(score=score, success=score > 0),
                unit_test_score=UnitTestScore(score=score),
                regression_score=RegressionScore(score=score),
                security_score=SecurityValidationScore(score=score),
                functional_score=FunctionalBehaviorScore(score=score),
                performance_score=PerformanceImpactScore(score=score),
            ))
        request = RankPatchesRequest(vulnerability_id="v1", validation_results=results)
        response = engine.rank_patches(request)
        assert response.ranking.total_patches == 5
        scores = [r.confidence_score for r in response.ranking.rankings]
        assert scores == sorted(scores, reverse=True)
        assert response.ranking.best_patch_id == "patch-4"
        assert response.ranking.worst_patch_id == "patch-0"

    def test_negative_historical_rate_clamped(self, engine):
        vr = PatchValidationResult(
            patch_id="p1",
            compilation_score=CompilationScore(score=1.0, success=True),
            unit_test_score=UnitTestScore(score=1.0),
            regression_score=RegressionScore(score=1.0),
            security_score=SecurityValidationScore(score=1.0),
            functional_score=FunctionalBehaviorScore(score=1.0),
            performance_score=PerformanceImpactScore(score=1.0),
        )
        result = engine.calculate_confidence(vr, historical_success_rate=-0.5)
        hist = next(f for f in result.feature_scores if f.feature == FeatureName.HISTORICAL_SUCCESS)
        assert hist.normalized_value == 0.0

    def test_result_has_created_at(self, engine, perfect_validation):
        result = engine.calculate_confidence(perfect_validation)
        assert result.created_at != ""

    def test_result_has_calculation_duration(self, engine, perfect_validation):
        result = engine.calculate_confidence(perfect_validation)
        assert result.calculation_duration_ms >= 0

    def test_service_creates_new_engines(self):
        service = ConfidenceService()
        e1 = service.get_engine("new-algo")
        e2 = service.get_engine("new-algo")
        assert e1 is e2

    def test_multiple_vulnerabilities_ranking(self, engine):
        vr1 = PatchValidationResult(
            patch_id="patch-a", vulnerability_id="vuln-1",
            compilation_score=CompilationScore(score=1.0, success=True),
            unit_test_score=UnitTestScore(score=1.0),
            regression_score=RegressionScore(score=1.0),
            security_score=SecurityValidationScore(score=1.0),
            functional_score=FunctionalBehaviorScore(score=1.0),
            performance_score=PerformanceImpactScore(score=1.0),
        )
        vr2 = PatchValidationResult(
            patch_id="patch-b", vulnerability_id="vuln-2",
            compilation_score=CompilationScore(score=0.5, success=True),
            unit_test_score=UnitTestScore(score=0.5),
            regression_score=RegressionScore(score=0.5),
            security_score=SecurityValidationScore(score=0.5),
            functional_score=FunctionalBehaviorScore(score=0.5),
            performance_score=PerformanceImpactScore(score=0.5),
        )
        request = RankPatchesRequest(
            vulnerability_id="vuln-1", validation_results=[vr1, vr2],
        )
        response = engine.rank_patches(request)
        assert response.ranking.rankings[0].confidence_score > response.ranking.rankings[1].confidence_score
