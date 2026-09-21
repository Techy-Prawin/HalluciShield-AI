"""
Tests for IEEE Research Analytics Dashboard API endpoint.
Verifies all 9 chart data shapes and data provenance.
"""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.agents.experiment_runner import experiment_runner
from app.agents.models import ExperimentMode, RunExperimentRequest

client = TestClient(app)


def _run_experiment_via_api():
    resp = client.post("/api/experiments/run", json={
        "experiment_name": "analytics-test",
        "modes": ["LLM_ONLY", "STATIC_SCANNER", "SINGLE_PATCH_LLM",
                   "MULTI_PATCH_LLM", "MULTI_PATCH_VALIDATION", "HALLUCISHIELD"],
    })
    assert resp.status_code == 200
    return resp.json()["experiment_id"]


@pytest.fixture(scope="module")
def experiment_id():
    return _run_experiment_via_api()


@pytest.fixture(scope="module")
def experiment_data(experiment_id):
    resp = client.get(f"/api/analytics/{experiment_id}/charts")
    assert resp.status_code == 200
    return resp.json()


class TestAnalyticsStructure:
    def test_has_experiment_id(self, experiment_data):
        assert experiment_data["experiment_id"].startswith("EXP-")

    def test_has_experiment_name(self, experiment_data):
        assert experiment_data["experiment_name"] == "analytics-test"

    def test_has_dataset_version(self, experiment_data):
        assert experiment_data["dataset_version"] == "v1.0"

    def test_has_dataset_hash(self, experiment_data):
        assert len(experiment_data["dataset_hash"]) == 16

    def test_has_total_test_cases(self, experiment_data):
        assert experiment_data["total_test_cases"] == 45

    def test_has_modes_compared(self, experiment_data):
        assert len(experiment_data["modes_compared"]) == 6

    def test_has_all_chart_keys(self, experiment_data):
        charts = experiment_data["charts"]
        expected_keys = {
            "detection_accuracy",
            "hallucination_precision_recall",
            "patch_success_rate",
            "regression_rate",
            "average_confidence",
            "confidence_vs_success",
            "baseline_comparison",
            "validation_time",
            "security_improvement",
        }
        assert set(charts.keys()) == expected_keys

    def test_has_data_provenance(self, experiment_data):
        prov = experiment_data["data_provenance"]
        assert prov["source"] == "stored_experiment_data"
        assert prov["records_used"] > 0
        assert "No synthetic" in prov["note"]


class TestDetectionAccuracyChart:
    def test_has_all_modes(self, experiment_data):
        data = experiment_data["charts"]["detection_accuracy"]
        assert len(data) == 6
        modes = {d["mode"] for d in data}
        expected = {"LLM_ONLY", "STATIC_SCANNER", "SINGLE_PATCH_LLM",
                    "MULTI_PATCH_LLM", "MULTI_PATCH_VALIDATION", "HALLUCISHIELD"}
        assert modes == expected

    def test_accuracy_values_between_0_and_100(self, experiment_data):
        for entry in experiment_data["charts"]["detection_accuracy"]:
            assert 0 <= entry["accuracy"] <= 100
            assert 0 <= entry["precision"] <= 100
            assert 0 <= entry["recall"] <= 100


class TestHallucinationPRChart:
    def test_has_all_modes(self, experiment_data):
        data = experiment_data["charts"]["hallucination_precision_recall"]
        assert len(data) == 6

    def test_f1_present(self, experiment_data):
        for entry in experiment_data["charts"]["hallucination_precision_recall"]:
            assert 0 <= entry["f1"] <= 100


class TestPatchSuccessChart:
    def test_has_all_modes(self, experiment_data):
        data = experiment_data["charts"]["patch_success_rate"]
        assert len(data) == 6

    def test_total_patches_non_negative(self, experiment_data):
        for entry in experiment_data["charts"]["patch_success_rate"]:
            assert entry["total_patches"] >= 0
            assert entry["validated"] >= 0


class TestRegressionChart:
    def test_has_all_modes(self, experiment_data):
        data = experiment_data["charts"]["regression_rate"]
        assert len(data) == 6

    def test_regression_rate_non_negative(self, experiment_data):
        for entry in experiment_data["charts"]["regression_rate"]:
            assert entry["regression_rate"] >= 0


class TestConfidenceChart:
    def test_has_all_modes(self, experiment_data):
        data = experiment_data["charts"]["average_confidence"]
        assert len(data) == 6

    def test_confidence_values_valid(self, experiment_data):
        for entry in experiment_data["charts"]["average_confidence"]:
            assert 0 <= entry["avg_confidence"] <= 100


class TestScatterChart:
    def test_has_entries(self, experiment_data):
        data = experiment_data["charts"]["confidence_vs_success"]
        assert len(data) > 0

    def test_entry_shape(self, experiment_data):
        for entry in experiment_data["charts"]["confidence_vs_success"][:5]:
            assert "test_id" in entry
            assert "confidence" in entry
            assert "success" in entry
            assert "mode" in entry
            assert entry["success"] in (0, 100)


class TestBaselineComparison:
    def test_has_metrics(self, experiment_data):
        data = experiment_data["charts"]["baseline_comparison"]
        assert len(data) == 5
        metric_names = {d["metric"] for d in data}
        assert "Detection Accuracy" in metric_names
        assert "Precision" in metric_names
        assert "F1 Score" in metric_names

    def test_has_both_systems(self, experiment_data):
        for entry in experiment_data["charts"]["baseline_comparison"]:
            assert "STATIC_SCANNER" in entry
            assert "HALLUCISHIELD" in entry


class TestValidationTimeChart:
    def test_has_all_modes(self, experiment_data):
        data = experiment_data["charts"]["validation_time"]
        assert len(data) == 6

    def test_time_positive(self, experiment_data):
        for entry in experiment_data["charts"]["validation_time"]:
            assert entry["avg_validation_time_ms"] >= 0


class TestSecurityImprovementChart:
    def test_has_categories(self, experiment_data):
        data = experiment_data["charts"]["security_improvement"]
        assert len(data) == 9

    def test_before_after_values(self, experiment_data):
        for entry in experiment_data["charts"]["security_improvement"]:
            assert "category" in entry
            assert 0 <= entry["before_patch"] <= 100
            assert 0 <= entry["after_patch"] <= 100


class TestAnalyticsLatest:
    def test_latest_404_when_no_experiments(self):
        original = experiment_runner.completed_runs[:]
        experiment_runner.completed_runs.clear()
        resp = client.get("/api/analytics/latest/charts")
        experiment_runner.completed_runs.extend(original)
        assert resp.status_code == 404

    def test_latest_returns_same_data(self):
        _run_experiment_via_api()
        resp = client.get("/api/analytics/latest/charts")
        assert resp.status_code == 200
        data = resp.json()
        assert "charts" in data
        assert len(data["charts"]) == 9
