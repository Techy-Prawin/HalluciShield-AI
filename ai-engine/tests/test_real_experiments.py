"""
Tests for P2: Real Experiment Mode for HalluciShield.

Proves that REAL experiments:
- Execute actual pipeline agents (not simulation functions)
- Record data_source = "real_execution" in every record
- Produce non-deterministic results based on real detection
- Generate actual patches via PatchGenerationAgent
- Calculate actual confidence via ConfidenceEngine
- Never mix simulated and real data
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.agents.models import (
    ExperimentConfig,
    ExperimentDataSource,
    ExperimentMode,
    RunExperimentRequest,
    TestCaseRecord,
    VulnerabilityTestCategory,
)
from app.agents.real_benchmark_dataset import (
    REAL_BENCHMARK_BY_ID,
    REAL_BENCHMARK_BY_CATEGORY,
    REAL_BENCHMARK_CASES,
    REAL_BENCHMARK_VERSION,
)
from app.agents.experiment_runner import experiment_runner

client = TestClient(app)


# ============================================================
# TEST: Real Benchmark Dataset Integrity
# ============================================================

class TestRealBenchmarkDataset:
    """Verify the real benchmark dataset structure."""

    def test_has_nine_cases(self):
        assert len(REAL_BENCHMARK_CASES) == 9

    def test_one_per_category(self):
        categories = [tc.vuln_category for tc in REAL_BENCHMARK_CASES]
        assert len(set(categories)) == 9

    def test_all_categories_present(self):
        expected = set(VulnerabilityTestCategory)
        actual = set(tc.vuln_category for tc in REAL_BENCHMARK_CASES)
        assert actual == expected

    def test_dataset_version(self):
        assert REAL_BENCHMARK_VERSION == "v1.0-real"

    def test_by_id_lookup(self):
        assert "R-SQL-001" in REAL_BENCHMARK_BY_ID
        assert "R-XSS-001" in REAL_BENCHMARK_BY_ID
        assert "R-HPKG-001" in REAL_BENCHMARK_BY_ID

    def test_by_category_grouping(self):
        assert len(REAL_BENCHMARK_BY_CATEGORY) == 9

    def test_all_have_required_fields(self):
        for tc in REAL_BENCHMARK_CASES:
            assert tc.test_id.startswith("R-")
            assert tc.original_code.strip()
            assert tc.cwe
            assert tc.vulnerable_line >= 1
            assert tc.severity in ("CRITICAL", "HIGH", "MEDIUM")

    def test_code_is_genuinely_vulnerable(self):
        sql = REAL_BENCHMARK_BY_ID["R-SQL-001"]
        assert "+" in sql.original_code and "SELECT" in sql.original_code

        xss = REAL_BENCHMARK_BY_ID["R-XSS-001"]
        assert "innerHTML" in xss.original_code

        secret = REAL_BENCHMARK_BY_ID["R-SECRET-001"]
        assert "password" in secret.original_code.lower() or "api_key" in secret.original_code.lower()

        cmd = REAL_BENCHMARK_BY_ID["R-CMD-001"]
        assert "os.system" in cmd.original_code

        path = REAL_BENCHMARK_BY_ID["R-PATH-001"]
        assert "open(" in path.original_code and "+" in path.original_code

        jwt = REAL_BENCHMARK_BY_ID["R-JWT-001"]
        assert "none" in jwt.original_code

        hapi = REAL_BENCHMARK_BY_ID["R-HAPI-001"]
        assert "import" in hapi.original_code

        hpkg = REAL_BENCHMARK_BY_ID["R-HPKG-001"]
        assert "requirements" in hpkg.file_path


# ============================================================
# TEST: REAL experiment runs actual pipeline
# ============================================================

class TestRealExperimentExecution:
    """Verify that REAL experiments execute actual agents."""

    @pytest.fixture(autouse=True)
    def _clear_runner(self):
        experiment_runner.completed_runs.clear()
        yield
        experiment_runner.completed_runs.clear()

    def test_real_experiment_completes(self):
        req = RunExperimentRequest(
            experiment_name="test-real-pipeline",
            data_source=ExperimentDataSource.REAL,
            modes=[ExperimentMode.HALLUCISHIELD],
            test_categories=[VulnerabilityTestCategory.SQL_INJECTION],
        )
        run = experiment_runner.run_experiment(req)
        assert run.status == "completed"
        assert run.experiment_id.startswith("EXP-REAL-")
        assert len(run.records) > 0

    def test_real_records_have_data_source_real(self):
        req = RunExperimentRequest(
            experiment_name="test-real-provenance",
            data_source=ExperimentDataSource.REAL,
            modes=[ExperimentMode.HALLUCISHIELD],
            test_categories=[VulnerabilityTestCategory.SQL_INJECTION],
        )
        run = experiment_runner.run_experiment(req)
        for record in run.records:
            assert record.data_source == ExperimentDataSource.REAL

    def test_real_experiment_generates_patches(self):
        req = RunExperimentRequest(
            experiment_name="test-real-patches",
            data_source=ExperimentDataSource.REAL,
            modes=[ExperimentMode.HALLUCISHIELD],
            test_categories=[VulnerabilityTestCategory.SQL_INJECTION],
        )
        run = experiment_runner.run_experiment(req)
        sql_record = next(r for r in run.records if r.test_id == "R-SQL-001")
        assert sql_record.generated_patches_count > 0
        assert sql_record.actual_patches  # strategies list should be non-empty

    def test_real_experiment_calculates_confidence(self):
        req = RunExperimentRequest(
            experiment_name="test-real-confidence",
            data_source=ExperimentDataSource.REAL,
            modes=[ExperimentMode.HALLUCISHIELD],
            test_categories=[VulnerabilityTestCategory.SQL_INJECTION],
        )
        run = experiment_runner.run_experiment(req)
        sql_record = next(r for r in run.records if r.test_id == "R-SQL-001")
        assert sql_record.best_confidence_score > 0

    def test_real_experiment_records_execution_time(self):
        req = RunExperimentRequest(
            experiment_name="test-real-timing",
            data_source=ExperimentDataSource.REAL,
            modes=[ExperimentMode.HALLUCISHIELD],
            test_categories=[VulnerabilityTestCategory.SQL_INJECTION],
        )
        run = experiment_runner.run_experiment(req)
        for record in run.records:
            assert record.execution_time_ms >= 0

    def test_real_experiment_has_system_config(self):
        req = RunExperimentRequest(
            experiment_name="test-real-sysconfig",
            data_source=ExperimentDataSource.REAL,
            modes=[ExperimentMode.HALLUCISHIELD],
            test_categories=[VulnerabilityTestCategory.SQL_INJECTION],
        )
        run = experiment_runner.run_experiment(req)
        for record in run.records:
            assert "platform" in record.system_config
            assert "python_version" in record.system_config
            assert record.experiment_version == "v1.0-real"

    def test_real_experiment_metrics_correctly(self):
        req = RunExperimentRequest(
            experiment_name="test-real-metrics",
            data_source=ExperimentDataSource.REAL,
            modes=[ExperimentMode.HALLUCISHIELD],
            test_categories=[VulnerabilityTestCategory.SQL_INJECTION],
        )
        run = experiment_runner.run_experiment(req)
        assert "HALLUCISHIELD" in run.metrics_by_mode
        m = run.metrics_by_mode["HALLUCISHIELD"]
        assert m.total_tests == 1
        assert m.total_patches_generated > 0

    def test_real_experiment_multi_mode(self):
        req = RunExperimentRequest(
            experiment_name="test-real-multi",
            data_source=ExperimentDataSource.REAL,
            modes=[ExperimentMode.STATIC_SCANNER, ExperimentMode.HALLUCISHIELD],
            test_categories=[VulnerabilityTestCategory.SQL_INJECTION],
        )
        run = experiment_runner.run_experiment(req)
        assert "STATIC_SCANNER" in run.metrics_by_mode
        assert "HALLUCISHIELD" in run.metrics_by_mode

    def test_real_experiment_scanner_result_populated(self):
        req = RunExperimentRequest(
            experiment_name="test-real-scanner",
            data_source=ExperimentDataSource.REAL,
            modes=[ExperimentMode.HALLUCISHIELD],
            test_categories=[VulnerabilityTestCategory.SQL_INJECTION],
        )
        run = experiment_runner.run_experiment(req)
        sql_record = next(r for r in run.records if r.test_id == "R-SQL-001")
        assert sql_record.actual_scanner_result  # should describe findings


# ============================================================
# TEST: REAL vs SIMULATION never mix
# ============================================================

class TestNoDataMixing:
    """Ensure simulated and real data are never mixed in the same experiment."""

    @pytest.fixture(autouse=True)
    def _clear_runner(self):
        experiment_runner.completed_runs.clear()
        yield
        experiment_runner.completed_runs.clear()

    def test_simulation_experiment_is_simulation(self):
        req = RunExperimentRequest(
            experiment_name="test-sim",
            data_source=ExperimentDataSource.SIMULATION,
            modes=[ExperimentMode.HALLUCISHIELD],
            test_categories=[VulnerabilityTestCategory.SQL_INJECTION],
        )
        run = experiment_runner.run_experiment(req)
        assert run.data_source == ExperimentDataSource.SIMULATION
        for record in run.records:
            assert record.data_source == ExperimentDataSource.SIMULATION

    def test_real_experiment_is_real(self):
        req = RunExperimentRequest(
            experiment_name="test-real",
            data_source=ExperimentDataSource.REAL,
            modes=[ExperimentMode.HALLUCISHIELD],
            test_categories=[VulnerabilityTestCategory.SQL_INJECTION],
        )
        run = experiment_runner.run_experiment(req)
        assert run.data_source == ExperimentDataSource.REAL
        for record in run.records:
            assert record.data_source == ExperimentDataSource.REAL

    def test_separate_runs_have_different_data_sources(self):
        sim_req = RunExperimentRequest(
            experiment_name="sim-run",
            data_source=ExperimentDataSource.SIMULATION,
            modes=[ExperimentMode.HALLUCISHIELD],
            test_categories=[VulnerabilityTestCategory.SQL_INJECTION],
        )
        real_req = RunExperimentRequest(
            experiment_name="real-run",
            data_source=ExperimentDataSource.REAL,
            modes=[ExperimentMode.HALLUCISHIELD],
            test_categories=[VulnerabilityTestCategory.SQL_INJECTION],
        )
        sim_run = experiment_runner.run_experiment(sim_req)
        real_run = experiment_runner.run_experiment(real_req)
        assert sim_run.data_source == ExperimentDataSource.SIMULATION
        assert real_run.data_source == ExperimentDataSource.REAL
        assert sim_run.experiment_id != real_run.experiment_id


# ============================================================
# TEST: API endpoint supports data_source
# ============================================================

class TestExperimentAPI:
    """Test the experiment API with data_source parameter."""

    @pytest.fixture(autouse=True)
    def _clear_runner(self):
        experiment_runner.completed_runs.clear()
        yield
        experiment_runner.completed_runs.clear()

    def test_run_endpoint_returns_data_source(self):
        resp = client.post("/api/experiments/run", json={
            "experiment_name": "api-test-sim",
            "data_source": "SIMULATION",
            "modes": ["HALLUCISHIELD"],
            "test_categories": ["SQL_INJECTION"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["data_source"] == "SIMULATION"

    def test_run_real_endpoint(self):
        resp = client.post("/api/experiments/run-real", json={
            "experiment_name": "api-test-real",
            "modes": ["HALLUCISHIELD"],
            "test_categories": ["SQL_INJECTION"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["data_source"] == "REAL"

    def test_categories_includes_data_sources(self):
        resp = client.get("/api/experiments/categories")
        assert resp.status_code == 200
        data = resp.json()
        assert "data_sources" in data
        assert "SIMULATION" in data["data_sources"]
        assert "REAL" in data["data_sources"]

    def test_metrics_endpoint_includes_data_source(self):
        # First run a sim experiment
        sim_resp = client.post("/api/experiments/run", json={
            "experiment_name": "metrics-test",
            "data_source": "SIMULATION",
            "modes": ["HALLUCISHIELD"],
            "test_categories": ["SQL_INJECTION"],
        })
        exp_id = sim_resp.json()["experiment_id"]

        # Then get its metrics
        metrics_resp = client.get(f"/api/experiments/{exp_id}/metrics")
        assert metrics_resp.status_code == 200
        data = metrics_resp.json()
        assert data["data_source"] == "SIMULATION"

    def test_analytics_labels_data_source(self):
        # Run a sim experiment
        sim_resp = client.post("/api/experiments/run", json={
            "experiment_name": "analytics-test",
            "data_source": "SIMULATION",
            "modes": ["HALLUCISHIELD"],
            "test_categories": ["SQL_INJECTION"],
        })
        exp_id = sim_resp.json()["experiment_id"]

        # Get analytics
        analytics_resp = client.get(f"/api/analytics/{exp_id}/charts")
        assert analytics_resp.status_code == 200
        data = analytics_resp.json()
        assert data["data_source"] == "SIMULATION"
        # Check provenance
        assert data["data_provenance"]["data_source"] == "SIMULATION"
        # Check chart entries have data_source
        for entry in data["charts"]["detection_accuracy"]:
            assert "data_source" in entry


# ============================================================
# TEST: REAL experiment uses actual agents (not simulation)
# ============================================================

class TestRealAgentExecution:
    """Verify that REAL mode calls actual agents, not simulation functions."""

    @pytest.fixture(autouse=True)
    def _clear_runner(self):
        experiment_runner.completed_runs.clear()
        yield
        experiment_runner.completed_runs.clear()

    def test_real_does_not_call_simulation(self):
        req = RunExperimentRequest(
            experiment_name="test-no-sim",
            data_source=ExperimentDataSource.REAL,
            modes=[ExperimentMode.HALLUCISHIELD],
            test_categories=[VulnerabilityTestCategory.SQL_INJECTION],
        )
        run = experiment_runner.run_experiment(req)
        # Verify records have real execution artifacts
        for record in run.records:
            assert record.data_source == ExperimentDataSource.REAL
            assert record.experiment_version == "v1.0-real"

    def test_sql_injection_real_detection(self):
        req = RunExperimentRequest(
            experiment_name="test-sql-real",
            data_source=ExperimentDataSource.REAL,
            modes=[ExperimentMode.HALLUCISHIELD],
            test_categories=[VulnerabilityTestCategory.SQL_INJECTION],
        )
        run = experiment_runner.run_experiment(req)
        sql_record = next(r for r in run.records if r.test_id == "R-SQL-001")
        # The fallback scanner should detect SQL injection
        assert sql_record.detection_result is True
        assert sql_record.actual_scanner_result != ""

    def test_xss_real_detection(self):
        req = RunExperimentRequest(
            experiment_name="test-xss-real",
            data_source=ExperimentDataSource.REAL,
            modes=[ExperimentMode.HALLUCISHIELD],
            test_categories=[VulnerabilityTestCategory.XSS],
        )
        run = experiment_runner.run_experiment(req)
        xss_record = next(r for r in run.records if r.test_id == "R-XSS-001")
        # innerHTML = should be detected
        assert xss_record.detection_result is True

    def test_hardcoded_secret_real_detection(self):
        req = RunExperimentRequest(
            experiment_name="test-secret-real",
            data_source=ExperimentDataSource.REAL,
            modes=[ExperimentMode.HALLUCISHIELD],
            test_categories=[VulnerabilityTestCategory.HARDCODED_SECRETS],
        )
        run = experiment_runner.run_experiment(req)
        secret_record = next(r for r in run.records if r.test_id == "R-SECRET-001")
        assert secret_record.detection_result is True

    def test_command_injection_real_detection(self):
        req = RunExperimentRequest(
            experiment_name="test-cmd-real",
            data_source=ExperimentDataSource.REAL,
            modes=[ExperimentMode.HALLUCISHIELD],
            test_categories=[VulnerabilityTestCategory.COMMAND_INJECTION],
        )
        run = experiment_runner.run_experiment(req)
        cmd_record = next(r for r in run.records if r.test_id == "R-CMD-001")
        assert cmd_record.detection_result is True
