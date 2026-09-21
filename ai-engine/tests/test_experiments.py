"""
Tests for research experiment framework.
"""
from fastapi.testclient import TestClient
from app.agents.experiment_runner import (
    ExperimentRunner, _compute_dataset_hash, _filter_test_cases,
    _detect_for_mode, _generate_patches_for_mode, _simulate_confidence_score,
    _compute_metrics, experiment_runner,
)
from app.agents.models import (
    ExperimentConfig, ExperimentMetrics, ExperimentMode, ExperimentRun,
    ExperimentSummary, RunExperimentRequest, TestCaseRecord,
    VulnerabilityTestCategory,
)
from app.agents.test_dataset import (
    ALL_TEST_CASES, ALL_TEST_CASES_BY_CATEGORY, ALL_TEST_CASES_BY_ID, DATASET_VERSION,
)
from app.main import app

client = TestClient(app)

class TestDatasetIntegrity:
    def test_dataset_has_45_cases(self):
        assert len(ALL_TEST_CASES) == 45

    def test_all_9_categories_present(self):
        categories = set(tc.vuln_category.value for tc in ALL_TEST_CASES)
        assert len(categories) == 9

    def test_five_cases_per_category(self):
        for cat, cases in ALL_TEST_CASES_BY_CATEGORY.items():
            assert len(cases) == 5

    def test_unique_test_ids(self):
        ids = [tc.test_id for tc in ALL_TEST_CASES]
        assert len(ids) == len(set(ids))

    def test_by_id_lookup(self):
        assert ALL_TEST_CASES_BY_ID["SQL-001"].severity == "CRITICAL"
        assert ALL_TEST_CASES_BY_ID["XSS-001"].severity == "HIGH"

    def test_dataset_version(self):
        assert DATASET_VERSION == "v1.0"

    def test_all_cases_have_required_fields(self):
        for tc in ALL_TEST_CASES:
            assert tc.test_id and tc.vuln_category and tc.vulnerability_type
            assert tc.severity in ("CRITICAL", "HIGH", "MEDIUM")
            assert tc.file_path and tc.original_code
            assert tc.vulnerable_line >= 1 and tc.description
            assert tc.cwe.startswith("CWE-")

    def test_dataset_hash_deterministic(self):
        h1 = _compute_dataset_hash(ALL_TEST_CASES)
        h2 = _compute_dataset_hash(ALL_TEST_CASES)
        assert h1 == h2 and len(h1) == 16

class TestDatasetFiltering:
    def test_filter_none_returns_all(self):
        assert len(_filter_test_cases(ALL_TEST_CASES, None)) == 45

    def test_filter_empty_returns_all(self):
        assert len(_filter_test_cases(ALL_TEST_CASES, [])) == 45

    def test_filter_single_category(self):
        result = _filter_test_cases(ALL_TEST_CASES, [VulnerabilityTestCategory.SQL_INJECTION])
        assert len(result) == 5

    def test_filter_multiple_categories(self):
        cats = [VulnerabilityTestCategory.XSS, VulnerabilityTestCategory.COMMAND_INJECTION]
        result = _filter_test_cases(ALL_TEST_CASES, cats)
        assert len(result) == 10

class TestDetectionSimulation:
    def test_static_scanner_sql_001(self):
        assert _detect_for_mode(ALL_TEST_CASES_BY_ID["SQL-001"], ExperimentMode.STATIC_SCANNER) is True

    def test_static_scanner_cmd_001(self):
        assert _detect_for_mode(ALL_TEST_CASES_BY_ID["CMD-001"], ExperimentMode.STATIC_SCANNER) is True

    def test_static_scanner_path_001(self):
        assert _detect_for_mode(ALL_TEST_CASES_BY_ID["PATH-001"], ExperimentMode.STATIC_SCANNER) is True

    def test_static_scanner_secret_001(self):
        assert _detect_for_mode(ALL_TEST_CASES_BY_ID["SECRET-001"], ExperimentMode.STATIC_SCANNER) is True

    def test_static_scanner_xss_001(self):
        assert _detect_for_mode(ALL_TEST_CASES_BY_ID["XSS-001"], ExperimentMode.STATIC_SCANNER) is True

    def test_static_scanner_jwt_001(self):
        assert _detect_for_mode(ALL_TEST_CASES_BY_ID["JWT-001"], ExperimentMode.STATIC_SCANNER) is False

    def test_static_scanner_auth_001(self):
        assert _detect_for_mode(ALL_TEST_CASES_BY_ID["AUTH-001"], ExperimentMode.STATIC_SCANNER) is False

    def test_static_scanner_hapi_001(self):
        assert _detect_for_mode(ALL_TEST_CASES_BY_ID["HAPI-001"], ExperimentMode.STATIC_SCANNER) is False

    def test_static_scanner_hpkg_001(self):
        assert _detect_for_mode(ALL_TEST_CASES_BY_ID["HPKG-001"], ExperimentMode.STATIC_SCANNER) is False

    def test_llm_only_sql_001(self):
        assert _detect_for_mode(ALL_TEST_CASES_BY_ID["SQL-001"], ExperimentMode.LLM_ONLY) is True

    def test_llm_only_hapi_001(self):
        assert _detect_for_mode(ALL_TEST_CASES_BY_ID["HAPI-001"], ExperimentMode.LLM_ONLY) is False

    def test_llm_only_hpkg_001(self):
        assert _detect_for_mode(ALL_TEST_CASES_BY_ID["HPKG-001"], ExperimentMode.LLM_ONLY) is False

    def test_hallucishield_detects_all(self):
        for tc in ALL_TEST_CASES:
            assert _detect_for_mode(tc, ExperimentMode.HALLUCISHIELD) is True

    def test_multi_validation_detects_all(self):
        for tc in ALL_TEST_CASES:
            assert _detect_for_mode(tc, ExperimentMode.MULTI_PATCH_VALIDATION) is True

    def test_static_detection_rate(self):
        detected = sum(1 for tc in ALL_TEST_CASES if _detect_for_mode(tc, ExperimentMode.STATIC_SCANNER))
        assert detected == 25

    def test_llm_detection_rate(self):
        detected = sum(1 for tc in ALL_TEST_CASES if _detect_for_mode(tc, ExperimentMode.LLM_ONLY))
        assert detected == 25

    def test_hallucishield_detection_rate(self):
        detected = sum(1 for tc in ALL_TEST_CASES if _detect_for_mode(tc, ExperimentMode.HALLUCISHIELD))
        assert detected == 45

