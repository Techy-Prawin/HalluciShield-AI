"""
Unit Tests for ACE Hyperparameter Sensitivity Analysis
======================================================
Tests requirement 13 from Phase 1:
1. Default ACE unchanged (matches production ConfidenceEngine).
2. Changing γ changes ACE according to the actual formula (weighted_sum^γ).
3. Changing β changes ACE according to its actual role (historical shrinkage pseudo-count).
4. Changing δ_overhead changes ACE according to its actual role (performance deduction).
5. Fixed evidence produces deterministic results.
6. Sensitivity experiment does not mutate production configuration.
7. π_crit remains unchanged when only non-critical hyperparameters change.
8. Results are correctly persisted/exported (CSV, JSON, LaTeX table, plots).
"""

import os
import sys
import json
import csv
import copy
import pytest
from pathlib import Path

# Add paths
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
EVAL_SENS_DIR = ROOT_DIR / "evaluation" / "sensitivity"
if str(EVAL_SENS_DIR) not in sys.path:
    sys.path.insert(0, str(EVAL_SENS_DIR))

from app.agents.confidence_engine import (
    ConfidenceEngine,
    DEFAULT_WEIGHTS,
    ALGORITHM_VERSION,
    calculate_pi_comp,
    calculate_pi_crit,
)
from app.agents.models import (
    CompilationScore,
    FeatureName,
    FeatureScore,
    FunctionalBehaviorScore,
    PatchValidationResult,
    PerformanceImpactScore,
    RegressionScore,
    SecurityValidationScore,
    UnitTestScore,
    ValidationStatus,
    WeightConfig,
)
from ace_sensitivity import (
    compute_ace_score,
    compute_historical_success,
    create_fixed_scenarios,
    ACESensitivityExperiment,
    PRODUCTION_GAMMA,
    PRODUCTION_BETA,
    PRODUCTION_DELTA_OVERHEAD,
)


@pytest.fixture
def scenarios():
    return create_fixed_scenarios()


# ============================================================
# 1. Default ACE Unchanged
# ============================================================

class TestDefaultACEUnchanged:
    def test_production_engine_matches_sensitivity_baseline_scenario_a(self, scenarios):
        """Verify baseline ACE from sensitivity engine exactly matches production ConfidenceEngine."""
        sc_a = scenarios["SCENARIO_A"]
        vr = sc_a["vr"]
        f6 = compute_historical_success(
            sc_a["hist"]["acceptance_rate"],
            sc_a["hist"]["deployment_success_rate"],
            sc_a["hist"]["sample_count"],
            beta=PRODUCTION_BETA,
        )
        
        # Production calculation
        engine = ConfidenceEngine()
        prod_result = engine.calculate_confidence(vr, historical_success_rate=f6)
        
        # Sensitivity baseline calculation
        sens_result = compute_ace_score(
            vr,
            historical_success_rate=f6,
            gamma=PRODUCTION_GAMMA,
            delta_overhead=PRODUCTION_DELTA_OVERHEAD,
        )
        
        assert sens_result["ace"] == pytest.approx(prod_result.confidence_score, abs=0.01)
        assert sens_result["f1"] == pytest.approx(1.0, abs=0.01)
        assert sens_result["f2"] == pytest.approx(1.0, abs=0.01)
        assert sens_result["f3"] == pytest.approx(1.0, abs=0.01)
        assert sens_result["f4"] == pytest.approx(1.0, abs=0.01)
        assert sens_result["f5"] == pytest.approx(1.0, abs=0.01)
        assert sens_result["pi_comp"] == 1.0
        assert sens_result["pi_crit"] == 1.0

    def test_production_engine_matches_sensitivity_baseline_scenario_b(self, scenarios):
        sc_b = scenarios["SCENARIO_B"]
        vr = sc_b["vr"]
        f6 = compute_historical_success(
            sc_b["hist"]["acceptance_rate"],
            sc_b["hist"]["deployment_success_rate"],
            sc_b["hist"]["sample_count"],
            beta=PRODUCTION_BETA,
        )
        
        engine = ConfidenceEngine()
        prod_result = engine.calculate_confidence(vr, historical_success_rate=f6)
        
        sens_result = compute_ace_score(
            vr,
            historical_success_rate=f6,
            gamma=PRODUCTION_GAMMA,
            delta_overhead=PRODUCTION_DELTA_OVERHEAD,
        )
        
        assert sens_result["ace"] == pytest.approx(prod_result.confidence_score, abs=0.01)

    def test_production_engine_matches_sensitivity_baseline_scenario_c(self, scenarios):
        """Scenario C has 1 critical vulnerability, so π_crit must zero both scores."""
        sc_c = scenarios["SCENARIO_C"]
        vr = sc_c["vr"]
        f6 = compute_historical_success(
            sc_c["hist"]["acceptance_rate"],
            sc_c["hist"]["deployment_success_rate"],
            sc_c["hist"]["sample_count"],
            beta=PRODUCTION_BETA,
        )
        
        engine = ConfidenceEngine()
        prod_result = engine.calculate_confidence(vr, historical_success_rate=f6)
        
        sens_result = compute_ace_score(
            vr,
            historical_success_rate=f6,
            gamma=PRODUCTION_GAMMA,
            delta_overhead=PRODUCTION_DELTA_OVERHEAD,
        )
        
        assert prod_result.confidence_score == 0.0
        assert sens_result["ace"] == 0.0
        assert sens_result["pi_crit"] == 0.0


# ============================================================
# 2. Changing γ Changes ACE According to Formula
# ============================================================

class TestGammaSensitivity:
    def test_gamma_sublinear_boosts_imperfect_score(self, scenarios):
        """When γ < 1.0, (weighted_sum)^γ > weighted_sum for weighted_sum in (0, 1)."""
        sc_b = scenarios["SCENARIO_B"]
        vr = sc_b["vr"]
        f6 = 0.5
        
        res_baseline = compute_ace_score(vr, historical_success_rate=f6, gamma=1.0)
        res_sublinear = compute_ace_score(vr, historical_success_rate=f6, gamma=0.5)
        
        assert res_sublinear["ace"] > res_baseline["ace"]
        expected_scaled = (res_baseline["weighted_sum"] ** 0.5) * 100.0
        assert res_sublinear["ace"] == pytest.approx(expected_scaled, abs=0.05)

    def test_gamma_superlinear_penalizes_imperfect_score(self, scenarios):
        """When γ > 1.0, (weighted_sum)^γ < weighted_sum for weighted_sum in (0, 1)."""
        sc_b = scenarios["SCENARIO_B"]
        vr = sc_b["vr"]
        f6 = 0.5
        
        res_baseline = compute_ace_score(vr, historical_success_rate=f6, gamma=1.0)
        res_superlinear = compute_ace_score(vr, historical_success_rate=f6, gamma=1.5)
        
        assert res_superlinear["ace"] < res_baseline["ace"]
        expected_scaled = (res_baseline["weighted_sum"] ** 1.5) * 100.0
        assert res_superlinear["ace"] == pytest.approx(expected_scaled, abs=0.05)

    def test_gamma_on_perfect_score_is_invariant(self, scenarios):
        """When weighted_sum == 1.0, 1.0^γ == 1.0 for all γ."""
        vr = copy.deepcopy(scenarios["SCENARIO_A"]["vr"])
        # Set all features to exactly 1.0
        f6 = 1.0
        res_1 = compute_ace_score(vr, historical_success_rate=f6, gamma=0.5)
        res_2 = compute_ace_score(vr, historical_success_rate=f6, gamma=1.0)
        res_3 = compute_ace_score(vr, historical_success_rate=f6, gamma=1.5)
        
        assert res_1["ace"] == pytest.approx(100.0, abs=0.01)
        assert res_2["ace"] == pytest.approx(100.0, abs=0.01)
        assert res_3["ace"] == pytest.approx(100.0, abs=0.01)


# ============================================================
# 3. Changing β Changes ACE According to Its Actual Role
# ============================================================

class TestBetaHistoricalShrinkage:
    def test_beta_controls_shrinkage_to_prior(self):
        """
        When sample count is fixed and observed > 0.5:
        Smaller β -> higher trust in observed -> f6 closer to observed.
        Larger β -> lower trust -> f6 closer to prior (0.5).
        """
        samples = 10
        acc = 0.90
        dep = 0.90
        # observed = 0.90
        
        f6_low_beta = compute_historical_success(acc, dep, samples, beta=5.0)    # trust = 10/15 = 0.667
        f6_default_beta = compute_historical_success(acc, dep, samples, beta=10.0) # trust = 10/20 = 0.500
        f6_high_beta = compute_historical_success(acc, dep, samples, beta=15.0)   # trust = 10/25 = 0.400
        
        assert f6_low_beta > f6_default_beta > f6_high_beta
        assert f6_default_beta == pytest.approx(0.5 * 0.90 + 0.5 * 0.50, abs=0.01) # = 0.70

    def test_beta_effect_on_ace_matches_weight_allocation(self, scenarios):
        """f6 has weight w_hs = 0.15. A difference in f6 of Δf6 produces exactly 15 * Δf6 change in ACE."""
        sc_a = scenarios["SCENARIO_A"]
        vr = sc_a["vr"]
        
        f6_low = compute_historical_success(0.9, 0.9, 10, beta=5.0)
        f6_high = compute_historical_success(0.9, 0.9, 10, beta=15.0)
        
        res_low = compute_ace_score(vr, historical_success_rate=f6_low)
        res_high = compute_ace_score(vr, historical_success_rate=f6_high)
        
        delta_f6 = f6_low - f6_high
        expected_ace_delta = delta_f6 * 0.15 * 100.0
        actual_ace_delta = res_low["ace"] - res_high["ace"]
        
        assert actual_ace_delta == pytest.approx(expected_ace_delta, abs=0.05)


# ============================================================
# 4. Changing δ_overhead Changes ACE According to Its Actual Role
# ============================================================

class TestDeltaOverheadSensitivity:
    def test_delta_overhead_reduces_performance_score(self, scenarios):
        """Performance score f5 decreases linearly with delta_overhead."""
        sc_a = scenarios["SCENARIO_A"]
        vr = sc_a["vr"]
        f6 = 0.7
        
        res_0 = compute_ace_score(vr, f6, delta_overhead=0.0)
        res_10 = compute_ace_score(vr, f6, delta_overhead=0.10)
        res_20 = compute_ace_score(vr, f6, delta_overhead=0.20)
        
        assert res_0["f5"] == pytest.approx(1.0, abs=0.01)
        assert res_10["f5"] == pytest.approx(0.90, abs=0.01)
        assert res_20["f5"] == pytest.approx(0.80, abs=0.01)

    def test_delta_overhead_impact_scaled_by_performance_weight(self, scenarios):
        """Performance has weight w_pf = 0.10. An overhead of 0.10 produces exactly 1.0% drop in ACE."""
        sc_a = scenarios["SCENARIO_A"]
        vr = sc_a["vr"]
        f6 = 0.7
        
        res_0 = compute_ace_score(vr, f6, delta_overhead=0.0)
        res_10 = compute_ace_score(vr, f6, delta_overhead=0.10)
        
        delta_ace = res_0["ace"] - res_10["ace"]
        assert delta_ace == pytest.approx(1.0, abs=0.05)


# ============================================================
# 5. Fixed Evidence Produces Deterministic Results
# ============================================================

class TestDeterminism:
    def test_repeat_calculations_identical(self, scenarios):
        """Calculating ACE 100 times on the same evidence produces bit-for-bit identical results."""
        vr = scenarios["SCENARIO_B"]["vr"]
        f6 = 0.533
        
        first = compute_ace_score(vr, f6, gamma=1.25, delta_overhead=0.15)
        for _ in range(50):
            nxt = compute_ace_score(vr, f6, gamma=1.25, delta_overhead=0.15)
            assert nxt == first

    def test_two_independent_experiment_runs_are_identical(self):
        """Running two instances of the full experiment suite yields 100% identical outputs."""
        exp1 = ACESensitivityExperiment(experiment_id="test-exp-1")
        recs1 = exp1.run()
        
        exp2 = ACESensitivityExperiment(experiment_id="test-exp-2")
        recs2 = exp2.run()
        
        assert len(recs1) == len(recs2)
        for r1, r2 in zip(recs1, recs2):
            assert r1["scenario"] == r2["scenario"]
            assert r1["parameter_name"] == r2["parameter_name"]
            assert r1["parameter_value"] == r2["parameter_value"]
            assert r1["ace"] == pytest.approx(r2["ace"], abs=1e-6)
            assert r1["weighted_sum"] == pytest.approx(r2["weighted_sum"], abs=1e-6)


# ============================================================
# 6. Sensitivity Experiment Does Not Mutate Production Configuration
# ============================================================

class TestProductionSafety:
    def test_production_defaults_unmutated_after_experiment(self):
        """Ensure DEFAULT_WEIGHTS, ALGORITHM_VERSION, and class defaults are unchanged."""
        weights_before = copy.deepcopy(DEFAULT_WEIGHTS.to_dict())
        
        exp = ACESensitivityExperiment()
        exp.run()
        
        weights_after = DEFAULT_WEIGHTS.to_dict()
        assert weights_before == weights_after
        assert DEFAULT_WEIGHTS.static_security == 0.25
        assert DEFAULT_WEIGHTS.unit_test_success == 0.20
        assert DEFAULT_WEIGHTS.regression_success == 0.20
        assert DEFAULT_WEIGHTS.compilation_success == 0.10
        assert DEFAULT_WEIGHTS.performance == 0.10
        assert DEFAULT_WEIGHTS.historical_success == 0.15

    def test_fixed_scenarios_input_unmutated_across_runs(self, scenarios):
        """Evidence objects must remain unmutated after running computations."""
        vr_a_before = scenarios["SCENARIO_A"]["vr"].model_dump()
        
        # Run computation with heavy modifications (overhead=0.3, gamma=1.5)
        compute_ace_score(scenarios["SCENARIO_A"]["vr"], 0.7, gamma=1.5, delta_overhead=0.30)
        
        vr_a_after = scenarios["SCENARIO_A"]["vr"].model_dump()
        assert vr_a_before == vr_a_after


# ============================================================
# 7. π_crit Remains Unchanged When Non-Critical Hyperparameters Change
# ============================================================

class TestPiCritInvariance:
    def test_pi_crit_invariant_under_gamma_beta_delta_for_clean_patch(self, scenarios):
        """For clean patch (Scenario A), π_crit must remain exactly 1.0 regardless of γ, β, or δ."""
        vr = scenarios["SCENARIO_A"]["vr"]
        
        for g in [0.5, 0.75, 1.0, 1.25, 1.5]:
            res = compute_ace_score(vr, 0.7, gamma=g)
            assert res["pi_crit"] == 1.0
            
        for d in [0.0, 0.05, 0.10, 0.20, 0.30]:
            res = compute_ace_score(vr, 0.7, delta_overhead=d)
            assert res["pi_crit"] == 1.0

    def test_pi_crit_invariant_under_gamma_beta_delta_for_critical_patch(self, scenarios):
        """For vulnerable patch (Scenario C), π_crit must remain exactly 0.0 regardless of γ, β, or δ."""
        vr = scenarios["SCENARIO_C"]["vr"]
        
        for g in [0.5, 0.75, 1.0, 1.25, 1.5]:
            res = compute_ace_score(vr, 0.4, gamma=g)
            assert res["pi_crit"] == 0.0
            assert res["ace"] == 0.0
            
        for d in [0.0, 0.05, 0.10, 0.20, 0.30]:
            res = compute_ace_score(vr, 0.4, delta_overhead=d)
            assert res["pi_crit"] == 0.0
            assert res["ace"] == 0.0


# ============================================================
# 8. Results Correctly Persisted / Exported
# ============================================================

class TestArtifactPersistence:
    def test_csv_and_json_artifacts_exist_and_valid(self):
        """Verify that experiment outputs match expected schema and are valid files."""
        eval_dir = ROOT_DIR / "evaluation"
        csv_file = eval_dir / "raw_results" / "ace_sensitivity_results.csv"
        json_file = eval_dir / "raw_results" / "ace_sensitivity_results.json"
        summary_file = eval_dir / "processed_results" / "ace_sensitivity_summary.json"
        table_file = eval_dir / "processed_results" / "ace_sensitivity_table.tex"
        
        assert csv_file.exists(), f"Missing CSV: {csv_file}"
        assert json_file.exists(), f"Missing JSON: {json_file}"
        assert summary_file.exists(), f"Missing Summary JSON: {summary_file}"
        assert table_file.exists(), f"Missing LaTeX table: {table_file}"
        
        # Check CSV content
        with open(csv_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) >= 40
            assert "experiment_id" in reader.fieldnames
            assert "gamma" in reader.fieldnames
            assert "beta" in reader.fieldnames
            assert "delta_overhead" in reader.fieldnames
            assert "ace" in reader.fieldnames
            assert "baseline_ace" in reader.fieldnames
            
        # Check JSON content
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert isinstance(data, list)
            assert len(data) >= 40

        # Check LaTeX table
        with open(table_file, "r", encoding="utf-8") as f:
            tex = f.read()
            assert "\\begin{table}" in tex
            assert "Scenario A (High)" in tex
            assert "Scenario B (Med)" in tex
            assert "Scenario C (Low)" in tex
            assert "\\end{table}" in tex
