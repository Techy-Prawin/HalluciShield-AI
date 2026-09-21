"""
TEST A-D: Proving Adaptive Learning Engine changes Confidence scoring.

Verifies that the P0 fix (connecting AdaptiveLearningEngine to ConfidenceEngine)
actually works end-to-end:
  - No historical data -> historical_success_rate = 0.5 (default)
  - After recording successful deployments -> historical_success_rate rises
  - After recording poor outcomes -> historical_success_rate falls
  - Confidence scores change meaningfully before and after learning
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.agents.adaptive_learning import AdaptiveLearningEngine
from app.agents.confidence_engine import ConfidenceEngine
from app.agents.models import PatchValidationResult, WeightConfig
from app.api.learning import engine as learning_engine

client = TestClient(app)


def _clear_learning_engine():
    """Reset learning engine state (avoid test pollution)."""
    learning_engine._records.clear()
    learning_engine._patterns.clear()


def _make_vr(patch_id: str, security_score: float = 0.9,
             unit_test_score: float = 0.8, perf_score: float = 0.7) -> dict:
    """Build a minimal PatchValidationResult dict."""
    return {
        "patch_id": patch_id,
        "compilation_score": {"score": 1.0, "success": True},
        "unit_test_score": {"score": unit_test_score},
        "regression_score": {"score": 1.0},
        "security_score": {"score": security_score},
        "functional_score": {"score": 1.0},
        "performance_score": {"score": perf_score},
        "validation_status": "PASS",
    }


def _rank_patches(vr_list, vuln_type=None, patch_strategies=None):
    """Call the rank endpoint and return the response."""
    payload = {
        "vulnerability_id": "vuln-integration-test",
        "validation_results": vr_list,
    }
    if vuln_type:
        payload["vulnerability_type"] = vuln_type
    if patch_strategies:
        payload["patch_strategies"] = patch_strategies
    return client.post(
        "/api/v1/vulnerabilities/vuln-integration-test/rank-patches",
        json=payload,
    )


def _get_confidence(response_json, patch_id):
    """Extract the confidence score for a specific patch_id from rank response."""
    for r in response_json["ranking"]["rankings"]:
        if r["patch_id"] == patch_id:
            return r["confidence_score"], r["feature_scores"]
    return None, None


def _get_historical_feature(response_json, patch_id):
    """Extract the historical_success feature score for a specific patch."""
    _, features = _get_confidence(response_json, patch_id)
    if features:
        for f in features:
            if f["feature"] == "historical_success":
                return f["normalized_value"], f["raw_value"]
    return None, None


def _record_successful_learning(vuln_id, patch_id, vuln_type, strategy,
                                 confidence_score=85.0, count=1):
    """Record successful learning events through the API."""
    for i in range(count):
        resp = client.post("/api/v1/learning/record", json={
            "vulnerability_id": vuln_id,
            "patch_id": patch_id,
            "vulnerability_type": vuln_type,
            "patch_strategy": strategy,
            "confidence_score": confidence_score,
            "developer_decision": "APPROVED",
            "deployment_outcome": "SUCCESS",
            "deployment_notes": f"Successful deployment #{i+1}",
        })
        assert resp.status_code == 201


def _record_failed_learning(vuln_id, patch_id, vuln_type, strategy,
                             confidence_score=50.0, count=1):
    """Record failed/rejected learning events through the API."""
    for i in range(count):
        resp = client.post("/api/v1/learning/record", json={
            "vulnerability_id": vuln_id,
            "patch_id": patch_id,
            "vulnerability_type": vuln_type,
            "patch_strategy": strategy,
            "confidence_score": confidence_score,
            "developer_decision": "REJECTED",
            "deployment_outcome": "FAILURE",
            "rejection_reason": "Failed in staging",
            "deployment_notes": f"Failed deployment #{i+1}",
        })
        assert resp.status_code == 201


# ============================================================
# TEST A: No historical data -> default historical rate
# ============================================================

class TestA_NoHistoricalData:
    """Baseline: rank patches with NO learning data recorded."""

    def setup_method(self):
        _clear_learning_engine()

    def test_baseline_confidence_scores(self):
        vr_a = _make_vr("patch-a-validated", security_score=0.95,
                        unit_test_score=0.9, perf_score=0.8)
        vr_b = _make_vr("patch-b-validated", security_score=0.80,
                        unit_test_score=0.7, perf_score=0.6)

        resp = _rank_patches(
            [vr_a, vr_b],
            vuln_type="SQL_INJECTION",
            patch_strategies={
                "patch-a-validated": "Parameterized Query",
                "patch-b-validated": "Input Validation",
            },
        )
        assert resp.status_code == 200
        data = resp.json()

        score_a, _ = _get_confidence(data, "patch-a-validated")
        score_b, _ = _get_confidence(data, "patch-b-validated")
        hist_a, hist_raw_a = _get_historical_feature(data, "patch-a-validated")
        hist_b, hist_raw_b = _get_historical_feature(data, "patch-b-validated")

        print("\n=== TEST A: Baseline (no learning data) ===")
        print(f"  patch-a confidence: {score_a:.2f}%")
        print(f"  patch-b confidence: {score_b:.2f}%")
        print(f"  patch-a historical_raw: {hist_raw_a:.4f} normalized: {hist_a:.4f}")
        print(f"  patch-b historical_raw: {hist_raw_b:.4f} normalized: {hist_b:.4f}")

        # Default historical rate = 0.5
        assert hist_raw_a == 0.5, f"Expected 0.5, got {hist_raw_a}"
        assert hist_raw_b == 0.5, f"Expected 0.5, got {hist_raw_b}"
        assert score_a > score_b, "patch-a should rank higher (better security+tests)"


# ============================================================
# TEST B: Record successes -> historical rate rises
# ============================================================

class TestB_RecordSuccesses:
    """Record 10 successful deployments for Parameterized Query strategy."""

    def setup_method(self):
        _clear_learning_engine()

    def test_successful_learning_increases_confidence(self):
        # --- Before learning (baseline) ---
        vr_a = _make_vr("patch-a-validated", security_score=0.95,
                        unit_test_score=0.9, perf_score=0.8)
        vr_b = _make_vr("patch-b-validated", security_score=0.80,
                        unit_test_score=0.7, perf_score=0.6)
        strategies = {
            "patch-a-validated": "Parameterized Query",
            "patch-b-validated": "Input Validation",
        }

        resp_before = _rank_patches(
            [vr_a, vr_b],
            vuln_type="SQL_INJECTION",
            patch_strategies=strategies,
        )
        assert resp_before.status_code == 200
        data_before = resp_before.json()
        score_a_before, _ = _get_confidence(data_before, "patch-a-validated")
        hist_a_before, _ = _get_historical_feature(data_before, "patch-a-validated")

        print("\n=== TEST B: After recording 10 successful deployments ===")
        print(f"  BEFORE learning:")
        print(f"    patch-a confidence: {score_a_before:.2f}%")
        print(f"    patch-a historical_raw: {hist_a_before:.4f}")

        # --- Record 10 successful learning events for patch-a's strategy ---
        _record_successful_learning(
            vuln_id="vuln-sql-001",
            patch_id="patch-a-validated",
            vuln_type="SQL_INJECTION",
            strategy="Parameterized Query",
            count=10,
        )

        # Verify pattern was extracted
        patterns = learning_engine.get_all_patterns()
        assert len(patterns) > 0, "Patterns should be extracted after recording"
        pat = learning_engine.get_historical_weight("SQL_INJECTION", "Parameterized Query")
        print(f"  Historical weight for Parameterized Query: {pat:.4f}")
        assert pat > 0.5, f"Expected >0.5 after successes, got {pat}"

        # --- After learning ---
        resp_after = _rank_patches(
            [vr_a, vr_b],
            vuln_type="SQL_INJECTION",
            patch_strategies=strategies,
        )
        assert resp_after.status_code == 200
        data_after = resp_after.json()
        score_a_after, _ = _get_confidence(data_after, "patch-a-validated")
        hist_a_after, _ = _get_historical_feature(data_after, "patch-a-validated")

        print(f"  AFTER learning:")
        print(f"    patch-a confidence: {score_a_after:.2f}%")
        print(f"    patch-a historical_raw: {hist_a_after:.4f}")
        print(f"    Delta confidence: +{score_a_after - score_a_before:.2f}%")
        print(f"    Delta historical: +{hist_a_after - hist_a_before:.4f}")

        # Historical rate must have increased
        assert hist_a_after > hist_a_before, (
            f"historical_raw should rise after successes: {hist_a_before:.4f} -> {hist_a_after:.4f}"
        )
        # Overall confidence must have increased
        assert score_a_after > score_a_before, (
            f"confidence should rise after successes: {score_a_before:.2f} -> {score_a_after:.2f}"
        )


# ============================================================
# TEST C: Record failures -> historical rate falls
# ============================================================

class TestC_RecordFailures:
    """Record failed outcomes for Input Validation strategy."""

    def setup_method(self):
        _clear_learning_engine()

    def test_failures_decrease_historical_rate(self):
        # Record 8 rejected/failed events for Input Validation
        _record_failed_learning(
            vuln_id="vuln-sql-002",
            patch_id="patch-b-validated",
            vuln_type="SQL_INJECTION",
            strategy="Input Validation",
            count=8,
        )

        hw = learning_engine.get_historical_weight("SQL_INJECTION", "Input Validation")
        print("\n=== TEST C: After 8 failed deployments for Input Validation ===")
        print(f"  Historical weight for Input Validation: {hw:.4f}")

        # With 8 failures and 0 successes, weight should be below default 0.5
        assert hw < 0.5, f"Expected <0.5 after failures, got {hw}"

        # Now rank and check Input Validation's historical feature
        vr_a = _make_vr("patch-a-validated", security_score=0.95,
                        unit_test_score=0.9, perf_score=0.8)
        vr_b = _make_vr("patch-b-validated", security_score=0.80,
                        unit_test_score=0.7, perf_score=0.6)
        strategies = {
            "patch-a-validated": "Parameterized Query",
            "patch-b-validated": "Input Validation",
        }
        resp = _rank_patches(
            [vr_a, vr_b],
            vuln_type="SQL_INJECTION",
            patch_strategies=strategies,
        )
        data = resp.json()

        hist_b, hist_raw_b = _get_historical_feature(data, "patch-b-validated")
        print(f"  patch-b historical_raw: {hist_raw_b:.4f} normalized: {hist_b:.4f}")

        # Input Validation's historical feature should be below 0.5
        assert hist_raw_b < 0.5, (
            f"Input Validation historical_raw should be <0.5, got {hist_raw_b}"
        )


# ============================================================
# TEST D: Confidence scores differ before and after learning
# ============================================================

class TestD_ConfidenceDiffers:
    """Full before/after comparison showing learning changes confidence."""

    def setup_method(self):
        _clear_learning_engine()

    def test_before_and_after_confidence_differ(self):
        vr_a = _make_vr("patch-a-validated", security_score=0.95,
                        unit_test_score=0.9, perf_score=0.8)
        vr_b = _make_vr("patch-b-validated", security_score=0.80,
                        unit_test_score=0.7, perf_score=0.6)
        strategies = {
            "patch-a-validated": "Parameterized Query",
            "patch-b-validated": "Input Validation",
        }

        # --- Before ---
        resp_before = _rank_patches(
            [vr_a, vr_b],
            vuln_type="SQL_INJECTION",
            patch_strategies=strategies,
        )
        data_before = resp_before.json()
        score_a_before, _ = _get_confidence(data_before, "patch-a-validated")
        score_b_before, _ = _get_confidence(data_before, "patch-b-validated")

        # --- Record successes for patch-a, failures for patch-b ---
        _record_successful_learning(
            vuln_id="vuln-sql-003", patch_id="patch-a-validated",
            vuln_type="SQL_INJECTION", strategy="Parameterized Query", count=15,
        )
        _record_failed_learning(
            vuln_id="vuln-sql-003", patch_id="patch-b-validated",
            vuln_type="SQL_INJECTION", strategy="Input Validation", count=10,
        )

        # --- After ---
        resp_after = _rank_patches(
            [vr_a, vr_b],
            vuln_type="SQL_INJECTION",
            patch_strategies=strategies,
        )
        data_after = resp_after.json()
        score_a_after, _ = _get_confidence(data_after, "patch-a-validated")
        score_b_after, _ = _get_confidence(data_after, "patch-b-validated")

        print("\n=== TEST D: Full before/after comparison ===")
        print(f"  patch-a (Parameterized Query):")
        print(f"    BEFORE: {score_a_before:.2f}%  ->  AFTER: {score_a_after:.2f}%  (delta: +{score_a_after - score_a_before:.2f}%)")
        print(f"  patch-b (Input Validation):")
        print(f"    BEFORE: {score_b_before:.2f}%  ->  AFTER: {score_b_after:.2f}%  (delta: {score_b_after - score_b_before:.2f}%)")
        print(f"  Gap between patches:")
        print(f"    BEFORE: {score_a_before - score_b_before:.2f}%")
        print(f"    AFTER:  {score_a_after - score_b_after:.2f}%")

        # Core assertions
        assert score_a_after > score_a_before, (
            f"patch-a confidence should rise: {score_a_before:.2f} -> {score_a_after:.2f}"
        )
        assert score_b_after < score_b_before, (
            f"patch-b confidence should fall: {score_b_before:.2f} -> {score_b_after:.2f}"
        )
        # The gap between patches should widen (learning makes good patches stand out)
        gap_before = score_a_before - score_b_before
        gap_after = score_a_after - score_b_after
        assert gap_after > gap_before, (
            f"Confidence gap should widen: {gap_before:.2f}% -> {gap_after:.2f}%"
        )
        print(f"\n  CONCLUSION: Learning integration is working correctly!")
        print(f"  Confidence gap widened from {gap_before:.2f}% to {gap_after:.2f}%")
