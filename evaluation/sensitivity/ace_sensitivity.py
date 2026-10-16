"""
Adaptive Confidence Engine (ACE) Hyperparameter Sensitivity Analysis Engine
===========================================================================
Part of HalluciShield AI Research Evaluation Framework.

Provides reproducible, deterministic sensitivity analysis for ACE hyperparameters:
  - γ (gamma): Confidence scaling exponent / curvature hyperparameter (default=1.0)
               and optional critical gate penalty factor when critical vulns exist.
  - β (beta): Historical shrinkage pseudo-count parameter (default=10.0 in adaptive learning)
              controlling convergence from prior (0.5) to empirical feedback.
  - δ_overhead: Performance overhead / regression fraction (default=0.0)
                affecting feature f5 (performance).

Production Defaults:
  All baseline runs use the exact production configuration:
    weights = {w_ss: 0.25, w_ut: 0.20, w_rg: 0.20, w_cp: 0.10, w_pf: 0.10, w_hs: 0.15}
    π_comp = 1.0 (success/NA) or 0.0 (fail)
    π_crit = 1.0 (clean) or 0.0 (critical > 0)
    γ = 1.0 (linear sum)
    β = 10.0 (shrinkage pseudo-count)
    δ_overhead = 0.0 (baseline overhead)
"""

import os
import sys
import math
import json
import csv
import time
import copy
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# Ensure ai-engine is in sys.path
AI_ENGINE_DIR = Path(__file__).resolve().parent.parent.parent / "ai-engine"
if str(AI_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(AI_ENGINE_DIR))

from app.agents.confidence_engine import (
    ConfidenceEngine,
    DEFAULT_WEIGHTS,
    ALGORITHM_VERSION,
    calculate_pi_comp,
    calculate_pi_crit,
    HISTORICAL_COLD_START_PRIOR,
)
from app.agents.models import (
    CompilationScore,
    ConfidenceResult,
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
from app.agents.adaptive_learning import _calculate_historical_weight

# Standard experimental grids around defaults
DEFAULT_GAMMA_GRID = [0.5, 0.75, 1.0, 1.25, 1.5]
DEFAULT_BETA_REL_GRID = [0.5, 0.75, 1.0, 1.25, 1.5]  # Multiplier on default beta=10 (5.0, 7.5, 10.0, 12.5, 15.0)
DEFAULT_DELTA_OVERHEAD_GRID = [0.0, 0.05, 0.10, 0.20, 0.30]  # 0% to 30% execution overhead

PRODUCTION_GAMMA = 1.0
PRODUCTION_BETA = 10.0
PRODUCTION_DELTA_OVERHEAD = 0.0


def compute_historical_success(
    acceptance_rate: float,
    deployment_success_rate: float,
    sample_count: int,
    beta: float = PRODUCTION_BETA,
) -> float:
    """
    Compute historical success rate f6 using the shrinkage estimator:
        trust = sample_count / (sample_count + beta)
        observed = 0.6 * acceptance_rate + 0.4 * deployment_success_rate
        f6 = trust * observed + (1 - trust) * 0.5
    """
    if sample_count <= 0:
        return HISTORICAL_COLD_START_PRIOR
    trust = sample_count / (sample_count + beta)
    observed = 0.6 * acceptance_rate + 0.4 * deployment_success_rate
    weight = trust * observed + (1.0 - trust) * HISTORICAL_COLD_START_PRIOR
    return max(0.0, min(1.0, weight))


def compute_ace_score(
    validation_result: PatchValidationResult,
    historical_success_rate: float,
    weights: WeightConfig = DEFAULT_WEIGHTS,
    gamma: float = PRODUCTION_GAMMA,
    pi_crit_override: Optional[float] = None,
    delta_overhead: float = 0.0,
) -> Dict[str, Any]:
    """
    Deterministic calculation of ACE confidence with experimental hyperparameter support.
    
    When gamma=1.0, pi_crit_override=None, delta_overhead=0.0:
    Result is bit-for-bit IDENTICAL to production ConfidenceEngine.calculate_confidence.
    
    Args:
        validation_result: Fixed patch validation result
        historical_success_rate: Computed f6 historical score
        weights: ACE feature weights (default: production weights)
        gamma: Exponent on weighted sum (default: 1.0)
        pi_crit_override: Optional soft penalty multiplier for critical gate (default: None -> hard gate)
        delta_overhead: Performance overhead fraction (0.0 to 1.0) deducted from f5
    
    Returns:
        Dict with full feature breakdown, gates, weighted sum, and final ACE.
    """
    # Clone VR to ensure fixed evidence is never mutated
    vr = copy.deepcopy(validation_result)
    
    # Apply delta_overhead to performance feature (f5)
    if delta_overhead > 0.0:
        base_perf = vr.performance_score.score
        vr.performance_score.score = max(0.0, min(1.0, base_perf - delta_overhead))
        vr.performance_score.time_regression_pct = max(
            vr.performance_score.time_regression_pct, delta_overhead * 100.0
        )
        if delta_overhead > 0.5:  # exceeds threshold
            vr.performance_score.within_acceptable_range = False

    engine = ConfidenceEngine(weights=weights)
    features = engine._extract_features(vr, historical_success_rate)
    
    # Feature scores
    f_map = {f.feature.value: f.normalized_value for f in features}
    f1 = f_map.get("static_security", 0.0)
    f2 = f_map.get("unit_test_success", 0.0)
    f3 = f_map.get("regression_success", 0.0)
    f4 = f_map.get("compilation_success", 0.0)
    f5 = f_map.get("performance", 0.0)
    f6 = f_map.get("historical_success", 0.0)
    
    weighted_sum = sum(f.weighted_score for f in features)
    
    # Multiplicative gates
    pi_comp = calculate_pi_comp(vr)
    if pi_crit_override is not None:
        # Soft penalty gate when critical vulnerabilities exist
        sec = vr.security_score
        pi_crit = 1.0 if sec.critical == 0 else pi_crit_override
    else:
        # Production hard gate
        pi_crit = calculate_pi_crit(vr)
    
    # Production ACE equation with curvature exponent gamma
    # When gamma == 1.0, weighted_sum ** 1.0 == weighted_sum
    if weighted_sum > 0:
        scaled_sum = math.pow(weighted_sum, gamma)
    else:
        scaled_sum = 0.0
        
    ace = 100.0 * pi_comp * pi_crit * scaled_sum
    clamped_ace = max(0.0, min(100.0, ace))
    
    return {
        "f1": round(f1, 4),
        "f2": round(f2, 4),
        "f3": round(f3, 4),
        "f4": round(f4, 4),
        "f5": round(f5, 4),
        "f6": round(f6, 4),
        "pi_comp": float(pi_comp),
        "pi_crit": float(pi_crit),
        "weighted_sum": round(weighted_sum, 4),
        "scaled_sum": round(scaled_sum, 4),
        "ace": round(clamped_ace, 2),
    }


def create_fixed_scenarios() -> Dict[str, Dict[str, Any]]:
    """
    Define fixed, deterministic evaluation evidence for the 3 research scenarios.
    
    Scenario A: High-Confidence Patch
        - 0 vulnerabilities, clean security scan (f1 = 1.0)
        - 20/20 unit tests pass (f2 = 1.0)
        - 15/15 regression tests pass (f3 = 1.0)
        - Compiles cleanly (f4 = 1.0)
        - Perfect performance, 0% regression (f5 = 1.0)
        - Strong historical record: 10 samples, 90% acceptance, 90% deployment (f6 = 0.845 with beta=10)
        - π_comp = 1.0, π_crit = 1.0
        
    Scenario B: Medium-Confidence Patch
        - Minor findings, 0 critical, 0 high (f1 = 0.95)
        - 17/20 unit tests pass (f2 = 0.85)
        - 14/15 regression tests pass, 1 minor regression (f3 = 0.90)
        - Compiles cleanly (f4 = 1.0)
        - 15% latency regression within acceptable limit (f5 = 0.85)
        - Moderate historical record: 5 samples, 60% acceptance, 60% deployment (f6 = 0.533 with beta=10)
        - π_comp = 1.0, π_crit = 1.0
        
    Scenario C: Low-Confidence Patch
        - 1 critical vulnerability remains (f1 = 0.30)
        - 19/20 unit tests pass (f2 = 0.95)
        - 15/15 regression tests pass (f3 = 1.0)
        - Compiles cleanly (f4 = 1.0)
        - Good performance (f5 = 0.90)
        - Poor historical record: 5 samples, 20% acceptance, 20% deployment (f6 = 0.400 with beta=10)
        - π_comp = 1.0, π_crit = 0.0 (Hard gate zeroes ACE; soft penalty evaluated in analysis)
    """
    # Scenario A: High Confidence
    vr_a = PatchValidationResult(
        patch_id="patch-scenario-a-high",
        vulnerability_id="VULN-AUTH-001",
        compilation_score=CompilationScore(score=1.0, success=True, language="python"),
        unit_test_score=UnitTestScore(score=1.0, total_tests=20, passed=20, failed=0),
        regression_score=RegressionScore(score=1.0, total_tests=15, passed=15, failed=0, regressions_found=0),
        security_score=SecurityValidationScore(score=1.0, vulnerabilities_found=0, critical=0, high=0),
        functional_score=FunctionalBehaviorScore(score=1.0, tests_run=20, behavior_preserved=True),
        performance_score=PerformanceImpactScore(score=1.0, within_acceptable_range=True, time_regression_pct=0.0),
        validation_status=ValidationStatus.PASS,
    )
    hist_a = {"sample_count": 10, "acceptance_rate": 0.90, "deployment_success_rate": 0.90}

    # Scenario B: Medium Confidence
    vr_b = PatchValidationResult(
        patch_id="patch-scenario-b-medium",
        vulnerability_id="VULN-SQLI-002",
        compilation_score=CompilationScore(score=1.0, success=True, language="python"),
        unit_test_score=UnitTestScore(score=0.85, total_tests=20, passed=17, failed=3),
        regression_score=RegressionScore(score=0.90, total_tests=15, passed=14, failed=1, regressions_found=1),
        security_score=SecurityValidationScore(score=0.95, vulnerabilities_found=1, critical=0, high=0, low=1),
        functional_score=FunctionalBehaviorScore(score=0.90, tests_run=20, behavior_preserved=True),
        performance_score=PerformanceImpactScore(score=0.85, within_acceptable_range=True, time_regression_pct=15.0),
        validation_status=ValidationStatus.WARNING,
    )
    hist_b = {"sample_count": 5, "acceptance_rate": 0.60, "deployment_success_rate": 0.60}

    # Scenario C: Low Confidence (Critical vulnerability remains)
    vr_c = PatchValidationResult(
        patch_id="patch-scenario-c-low",
        vulnerability_id="VULN-CMD-003",
        compilation_score=CompilationScore(score=1.0, success=True, language="python"),
        unit_test_score=UnitTestScore(score=0.95, total_tests=20, passed=19, failed=1),
        regression_score=RegressionScore(score=1.0, total_tests=15, passed=15, failed=0, regressions_found=0),
        security_score=SecurityValidationScore(score=0.30, vulnerabilities_found=1, critical=1, high=0),
        functional_score=FunctionalBehaviorScore(score=1.0, tests_run=20, behavior_preserved=True),
        performance_score=PerformanceImpactScore(score=0.90, within_acceptable_range=True, time_regression_pct=5.0),
        validation_status=ValidationStatus.WARNING,
    )
    hist_c = {"sample_count": 5, "acceptance_rate": 0.20, "deployment_success_rate": 0.20}

    return {
        "SCENARIO_A": {
            "name": "Scenario A (High-Confidence)",
            "description": "Strong security evidence, all tests pass, zero regressions, clean compilation, positive history",
            "vr": vr_a,
            "hist": hist_a,
        },
        "SCENARIO_B": {
            "name": "Scenario B (Medium-Confidence)",
            "description": "Mixed evidence, minor test/regression imperfections, acceptable latency, moderate history",
            "vr": vr_b,
            "hist": hist_b,
        },
        "SCENARIO_C": {
            "name": "Scenario C (Low-Confidence)",
            "description": "Critical vulnerability remains post-patch (π_crit=0), poor historical feedback",
            "vr": vr_c,
            "hist": hist_c,
        },
    }


class ACESensitivityExperiment:
    """
    Executes controlled sensitivity analysis for ACE hyperparameters.
    """

    def __init__(
        self,
        gamma_grid: Optional[List[float]] = None,
        beta_rel_grid: Optional[List[float]] = None,
        delta_overhead_grid: Optional[List[float]] = None,
        experiment_id: Optional[str] = None,
    ):
        self.gamma_grid = gamma_grid or DEFAULT_GAMMA_GRID
        self.beta_rel_grid = beta_rel_grid or DEFAULT_BETA_REL_GRID
        self.delta_overhead_grid = delta_overhead_grid or DEFAULT_DELTA_OVERHEAD_GRID
        self.experiment_id = experiment_id or f"ace-sens-{int(time.time())}"
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.code_version = ALGORITHM_VERSION
        self.scenarios = create_fixed_scenarios()
        self.records: List[Dict[str, Any]] = []
        self.baselines: Dict[str, Dict[str, Any]] = {}

    def run(self) -> List[Dict[str, Any]]:
        """Run complete sensitivity grid over all scenarios with fixed evidence."""
        self.records = []
        self._compute_baselines()

        # 1. Baseline Configurations
        for sc_key, sc_data in self.scenarios.items():
            base_res = self.baselines[sc_key]
            self.records.append(self._make_record(
                parameter_name="baseline",
                parameter_value=1.0,
                gamma=PRODUCTION_GAMMA,
                beta=PRODUCTION_BETA,
                delta_overhead=PRODUCTION_DELTA_OVERHEAD,
                scenario=sc_key,
                metrics=base_res,
                baseline_ace=base_res["ace"],
            ))

        # 2. Gamma Variation (γ in [0.5, 0.75, 1.0, 1.25, 1.5])
        for sc_key, sc_data in self.scenarios.items():
            base_ace = self.baselines[sc_key]["ace"]
            f6 = compute_historical_success(
                sc_data["hist"]["acceptance_rate"],
                sc_data["hist"]["deployment_success_rate"],
                sc_data["hist"]["sample_count"],
                beta=PRODUCTION_BETA,
            )
            for g in self.gamma_grid:
                if g == PRODUCTION_GAMMA:
                    continue  # already in baseline
                res = compute_ace_score(
                    sc_data["vr"],
                    historical_success_rate=f6,
                    gamma=g,
                    delta_overhead=PRODUCTION_DELTA_OVERHEAD,
                )
                self.records.append(self._make_record(
                    parameter_name="gamma",
                    parameter_value=g,
                    gamma=g,
                    beta=PRODUCTION_BETA,
                    delta_overhead=PRODUCTION_DELTA_OVERHEAD,
                    scenario=sc_key,
                    metrics=res,
                    baseline_ace=base_ace,
                ))

        # 3. Beta Variation (Historical shrinkage: β_rel in [0.5, 0.75, 1.0, 1.25, 1.5])
        for sc_key, sc_data in self.scenarios.items():
            base_ace = self.baselines[sc_key]["ace"]
            for b_rel in self.beta_rel_grid:
                if b_rel == 1.0:
                    continue  # already in baseline
                real_beta = PRODUCTION_BETA * b_rel
                f6 = compute_historical_success(
                    sc_data["hist"]["acceptance_rate"],
                    sc_data["hist"]["deployment_success_rate"],
                    sc_data["hist"]["sample_count"],
                    beta=real_beta,
                )
                res = compute_ace_score(
                    sc_data["vr"],
                    historical_success_rate=f6,
                    gamma=PRODUCTION_GAMMA,
                    delta_overhead=PRODUCTION_DELTA_OVERHEAD,
                )
                self.records.append(self._make_record(
                    parameter_name="beta",
                    parameter_value=b_rel,
                    gamma=PRODUCTION_GAMMA,
                    beta=real_beta,
                    delta_overhead=PRODUCTION_DELTA_OVERHEAD,
                    scenario=sc_key,
                    metrics=res,
                    baseline_ace=base_ace,
                ))

        # 4. Delta Overhead Variation (δ_overhead in [0.0, 0.05, 0.10, 0.20, 0.30])
        for sc_key, sc_data in self.scenarios.items():
            base_ace = self.baselines[sc_key]["ace"]
            f6 = compute_historical_success(
                sc_data["hist"]["acceptance_rate"],
                sc_data["hist"]["deployment_success_rate"],
                sc_data["hist"]["sample_count"],
                beta=PRODUCTION_BETA,
            )
            for d in self.delta_overhead_grid:
                if d == PRODUCTION_DELTA_OVERHEAD:
                    continue  # already in baseline
                res = compute_ace_score(
                    sc_data["vr"],
                    historical_success_rate=f6,
                    gamma=PRODUCTION_GAMMA,
                    delta_overhead=d,
                )
                self.records.append(self._make_record(
                    parameter_name="delta_overhead",
                    parameter_value=d,
                    gamma=PRODUCTION_GAMMA,
                    beta=PRODUCTION_BETA,
                    delta_overhead=d,
                    scenario=sc_key,
                    metrics=res,
                    baseline_ace=base_ace,
                ))

        # 5. Soft Critical Gate Sensitivity (Evaluation of γ_crit soft penalty for Scenario C)
        # Evaluates what happens if π_crit is relaxed from 0.0 to paper's 0.4 penalty or 0.2-0.6
        sc_c_data = self.scenarios["SCENARIO_C"]
        f6_c = compute_historical_success(
            sc_c_data["hist"]["acceptance_rate"],
            sc_c_data["hist"]["deployment_success_rate"],
            sc_c_data["hist"]["sample_count"],
            beta=PRODUCTION_BETA,
        )
        base_ace_c = self.baselines["SCENARIO_C"]["ace"]
        for pi_crit_val in [0.1, 0.2, 0.3, 0.4, 0.5]:
            res_soft = compute_ace_score(
                sc_c_data["vr"],
                historical_success_rate=f6_c,
                gamma=PRODUCTION_GAMMA,
                pi_crit_override=pi_crit_val,
                delta_overhead=PRODUCTION_DELTA_OVERHEAD,
            )
            self.records.append(self._make_record(
                parameter_name="pi_crit_soft",
                parameter_value=pi_crit_val,
                gamma=PRODUCTION_GAMMA,
                beta=PRODUCTION_BETA,
                delta_overhead=PRODUCTION_DELTA_OVERHEAD,
                scenario="SCENARIO_C",
                metrics=res_soft,
                baseline_ace=base_ace_c,
            ))

        return self.records

    def _compute_baselines(self):
        """Compute exact production baseline for each scenario."""
        for sc_key, sc_data in self.scenarios.items():
            f6 = compute_historical_success(
                sc_data["hist"]["acceptance_rate"],
                sc_data["hist"]["deployment_success_rate"],
                sc_data["hist"]["sample_count"],
                beta=PRODUCTION_BETA,
            )
            res = compute_ace_score(
                sc_data["vr"],
                historical_success_rate=f6,
                gamma=PRODUCTION_GAMMA,
                delta_overhead=PRODUCTION_DELTA_OVERHEAD,
            )
            self.baselines[sc_key] = res

    def _make_record(
        self,
        parameter_name: str,
        parameter_value: float,
        gamma: float,
        beta: float,
        delta_overhead: float,
        scenario: str,
        metrics: Dict[str, Any],
        baseline_ace: float,
    ) -> Dict[str, Any]:
        ace = metrics["ace"]
        ace_delta = round(ace - baseline_ace, 2)
        pct_change = round((ace_delta / baseline_ace) * 100.0, 2) if baseline_ace > 0 else 0.0
        return {
            "experiment_id": self.experiment_id,
            "timestamp": self.timestamp,
            "code_version": self.code_version,
            "parameter_name": parameter_name,
            "parameter_value": parameter_value,
            "gamma": gamma,
            "beta": beta,
            "delta_overhead": delta_overhead,
            "scenario": scenario,
            "f1": metrics["f1"],
            "f2": metrics["f2"],
            "f3": metrics["f3"],
            "f4": metrics["f4"],
            "f5": metrics["f5"],
            "f6": metrics["f6"],
            "pi_comp": metrics["pi_comp"],
            "pi_crit": metrics["pi_crit"],
            "weighted_sum": metrics["weighted_sum"],
            "ace": ace,
            "baseline_ace": baseline_ace,
            "ace_delta": ace_delta,
            "pct_change": pct_change,
        }

    def compute_statistics(self) -> Dict[str, Any]:
        """Compute statistical robustness summary across parameters and scenarios."""
        summary: Dict[str, Any] = {
            "experiment_id": self.experiment_id,
            "timestamp": self.timestamp,
            "code_version": self.code_version,
            "scenarios": {},
            "parameter_effects": {},
        }

        for sc_key in self.scenarios.keys():
            sc_records = [r for r in self.records if r["scenario"] == sc_key]
            base_ace = self.baselines[sc_key]["ace"]
            
            sc_summary: Dict[str, Any] = {
                "baseline_ace": base_ace,
                "parameters": {},
            }
            
            for param in ["gamma", "beta", "delta_overhead", "pi_crit_soft"]:
                param_records = [r for r in sc_records if r["parameter_name"] in (param, "baseline")]
                if not param_records or len(param_records) <= 1:
                    continue
                scores = [r["ace"] for r in param_records]
                deltas = [r["ace_delta"] for r in param_records]
                
                n = len(scores)
                mean_ace = sum(scores) / n
                variance = sum((s - mean_ace) ** 2 for s in scores) / n if n > 0 else 0.0
                std_dev = math.sqrt(variance)
                
                max_abs_delta = max(abs(d) for d in deltas)
                
                # Classify parameter effect
                if max_abs_delta == 0.0:
                    effect = "INVARIANT (Gated to 0.0)"
                elif max_abs_delta < 2.0:
                    effect = "HIGHLY ROBUST (Minimal sensitivity: Delta < 2.0%)"
                elif max_abs_delta < 6.0:
                    effect = "MODERATELY ROBUST (Controlled sensitivity: Delta < 6.0%)"
                else:
                    effect = "HIGHLY SENSITIVE (Significant variation: Delta >= 6.0%)"
                
                sc_summary["parameters"][param] = {
                    "count": n,
                    "min_ace": round(min(scores), 2),
                    "max_ace": round(max(scores), 2),
                    "mean_ace": round(mean_ace, 2),
                    "std_dev": round(std_dev, 2),
                    "max_abs_delta": round(max_abs_delta, 2),
                    "effect": effect,
                    "values": [
                        {
                            "val": r["parameter_value"],
                            "ace": r["ace"],
                            "delta": r["ace_delta"],
                            "pct_change": r["pct_change"],
                        }
                        for r in param_records
                    ],
                }
            
            summary["scenarios"][sc_key] = sc_summary

        return summary
