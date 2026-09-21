"""
Tests for Adaptive Learning Engine (Milestone 16).
"""
import math
import pytest
from uuid import uuid4
from app.agents.adaptive_learning import (
    AdaptiveLearningEngine,
    _wilson_score_interval,
    _calculate_historical_weight,
    MODEL_VERSION,
    MIN_SAMPLES_FOR_PATTERN,
)
from app.agents.models import (
    ApprovalDecision,
    DeploymentOutcome,
    RecordDeploymentOutcomeRequest,
    RecordLearningRequest,
    WeightConfig,
)


class TestWilsonScoreInterval:
    def test_zero_total(self):
        lower, upper = _wilson_score_interval(0, 0)
        assert lower == 0.0
        assert upper == 1.0

    def test_all_success(self):
        lower, upper = _wilson_score_interval(10, 10)
        assert upper > lower
        assert upper <= 1.0
        assert lower > 0.5

    def test_all_failure(self):
        lower, upper = _wilson_score_interval(0, 10)
        assert lower >= 0.0
        assert upper < 0.5

    def test_half_success(self):
        lower, upper = _wilson_score_interval(5, 10)
        assert 0.2 < lower < 0.5
        assert 0.5 < upper < 0.8

    def test_larger_sample_narrower_interval(self):
        lo1, hi1 = _wilson_score_interval(50, 100)
        lo2, hi2 = _wilson_score_interval(500, 1000)
        assert (hi1 - lo1) > (hi2 - lo2)


class TestHistoricalWeight:
    def test_default_prior(self):
        w = _calculate_historical_weight(0.5, 0.5, 0)
        assert abs(w - 0.5) < 0.01

    def test_perfect_outcomes(self):
        w = _calculate_historical_weight(1.0, 1.0, 50)
        assert w > 0.8

    def test_poor_outcomes(self):
        w = _calculate_historical_weight(0.0, 0.0, 50)
        assert w < 0.2

    def test_few_samples_close_to_prior(self):
        w = _calculate_historical_weight(1.0, 1.0, 1)
        assert w < 0.7

    def test_many_samples_strong_signal(self):
        w = _calculate_historical_weight(1.0, 1.0, 1000)
        assert w > 0.9

    def test_clamped_0_1(self):
        w = _calculate_historical_weight(1.0, 1.0, 10000)
        assert 0.0 <= w <= 1.0


class TestLearningEventRecording:
    def setup_method(self):
        self.engine = AdaptiveLearningEngine()

    def test_record_event(self):
        req = RecordLearningRequest(
            vulnerability_id="vuln-1",
            patch_id="patch-1",
            vulnerability_type="sql_injection",
            patch_strategy="parameterized_queries",
            validation_features={"test_pass": True},
            confidence_score=0.85,
            developer_decision=ApprovalDecision.APPROVED,
            developer_id="dev-1",
        )
        rec = self.engine.record_learning_event(req)
        assert rec.id.startswith("lrn-")
        assert rec.vulnerability_id == "vuln-1"
        assert rec.model_version == MODEL_VERSION

    def test_record_multiple(self):
        for i in range(3):
            req = RecordLearningRequest(
                vulnerability_id=f"vuln-{i}",
                patch_id=f"patch-{i}",
                vulnerability_type="xss",
                patch_strategy="escaping",
                validation_features={},
                confidence_score=0.7,
                developer_decision=ApprovalDecision.APPROVED,
                developer_id="dev-1",
            )
            self.engine.record_learning_event(req)
        assert len(self.engine._records) == 3


class TestDeploymentOutcome:
    def setup_method(self):
        self.engine = AdaptiveLearningEngine()

    def test_record_deployment(self):
        req = RecordLearningRequest(
            vulnerability_id="vuln-1",
            patch_id="patch-1",
            vulnerability_type="sql_injection",
            patch_strategy="parameterized_queries",
            validation_features={},
            confidence_score=0.8,
            developer_decision=ApprovalDecision.APPROVED,
            developer_id="dev-1",
        )
        self.engine.record_learning_event(req)
        dep_req = RecordDeploymentOutcomeRequest(
            vulnerability_id="vuln-1",
            patch_id="patch-1",
            deployment_outcome=DeploymentOutcome.SUCCESS,
            notes="Deployed successfully",
        )
        updated = self.engine.record_deployment_outcome(dep_req)
        assert updated is not None
        assert updated.deployment_outcome == DeploymentOutcome.SUCCESS

    def test_deployment_not_found(self):
        dep_req = RecordDeploymentOutcomeRequest(
            vulnerability_id="nonexistent",
            patch_id="nonexistent",
            deployment_outcome=DeploymentOutcome.FAILURE,
        )
        result = self.engine.record_deployment_outcome(dep_req)
        assert result is None


class TestPatternExtraction:
    def setup_method(self):
        self.engine = AdaptiveLearningEngine()

    def _add_records(self, vuln_type, strategy, decisions, outcomes):
        for dec, out in zip(decisions, outcomes):
            req = RecordLearningRequest(
                vulnerability_id=f"vuln-{uuid4().hex[:8]}",
                patch_id=f"patch-{uuid4().hex[:8]}",
                vulnerability_type=vuln_type,
                patch_strategy=strategy,
                validation_features={},
                confidence_score=0.8,
                developer_decision=dec,
                developer_id="dev-1",
            )
            rec = self.engine.record_learning_event(req)
            if out != DeploymentOutcome.UNKNOWN:
                dep = RecordDeploymentOutcomeRequest(
                    vulnerability_id=rec.vulnerability_id,
                    patch_id=rec.patch_id,
                    deployment_outcome=out,
                )
                self.engine.record_deployment_outcome(dep)

    def test_extract_patterns(self):
        self._add_records(
            "sql_injection", "parameterized_queries",
            [ApprovalDecision.APPROVED] * 8 + [ApprovalDecision.REJECTED] * 2,
            [DeploymentOutcome.SUCCESS] * 7 + [DeploymentOutcome.FAILURE] + [DeploymentOutcome.UNKNOWN] * 2,
        )
        patterns = self.engine.extract_patterns()
        assert len(patterns) == 1
        p = patterns[0]
        assert p.vulnerability_type == "sql_injection"
        assert p.patch_strategy == "parameterized_queries"
        assert p.sample_count == 10
        assert p.acceptance_rate == 0.8

    def test_get_historical_weight_default(self):
        w = self.engine.get_historical_weight("unknown_type", "unknown_strategy")
        assert w == 0.5

    def test_get_patterns_for_vulnerability(self):
        self._add_records(
            "xss", "escaping",
            [ApprovalDecision.APPROVED] * 4,
            [DeploymentOutcome.SUCCESS] * 4,
        )
        patterns = self.engine.get_patterns_for_vulnerability("xss")
        assert len(patterns) == 1
        assert patterns[0].vulnerability_type == "xss"

    def test_multiple_pattern_types(self):
        self._add_records(
            "sql_injection", "parameterized_queries",
            [ApprovalDecision.APPROVED] * 4,
            [DeploymentOutcome.SUCCESS] * 4,
        )
        self._add_records(
            "xss", "escaping",
            [ApprovalDecision.APPROVED] * 3,
            [DeploymentOutcome.SUCCESS] * 3,
        )
        patterns = self.engine.extract_patterns()
        assert len(patterns) == 2

    def test_patterns_sorted_by_sample_count(self):
        self._add_records(
            "sql_injection", "parameterized_queries",
            [ApprovalDecision.APPROVED] * 10,
            [DeploymentOutcome.SUCCESS] * 10,
        )
        self._add_records(
            "xss", "escaping",
            [ApprovalDecision.APPROVED] * 3,
            [DeploymentOutcome.SUCCESS] * 3,
        )
        patterns = self.engine.extract_patterns()
        assert patterns[0].sample_count >= patterns[1].sample_count


class TestWeightAdjustment:
    def setup_method(self):
        self.engine = AdaptiveLearningEngine()

    def _populate(self):
        for i in range(5):
            req = RecordLearningRequest(
                vulnerability_id=f"vuln-{uuid4().hex[:8]}",
                patch_id=f"patch-{uuid4().hex[:8]}",
                vulnerability_type="sql_injection",
                patch_strategy="parameterized_queries",
                validation_features={},
                confidence_score=0.9,
                developer_decision=ApprovalDecision.APPROVED,
                developer_id="dev-1",
            )
            self.engine.record_learning_event(req)
        self.engine.extract_patterns()

    def test_suggest_adjustment(self):
        self._populate()
        adj, msg = self.engine.suggest_weight_adjustment()
        assert adj is not None
        assert "adjustment" in msg.lower()

    def test_no_patterns_no_adjustment(self):
        adj, msg = self.engine.suggest_weight_adjustment()
        assert adj is None

    def test_apply_adjustment(self):
        self._populate()
        adj, _ = self.engine.suggest_weight_adjustment()
        old_ver = self.engine.model_version
        self.engine.apply_weight_adjustment(adj)
        assert self.engine.model_version != old_ver

    def test_adjustment_history(self):
        self._populate()
        adj, _ = self.engine.suggest_weight_adjustment()
        self.engine.apply_weight_adjustment(adj)
        history = self.engine.get_adjustment_history()
        assert len(history) >= 1

    def test_adjustment_records_pattern_ids(self):
        self._populate()
        adj, _ = self.engine.suggest_weight_adjustment()
        assert len(adj.patterns_used) > 0

    def test_adjustment_has_reason(self):
        self._populate()
        adj, _ = self.engine.suggest_weight_adjustment()
        assert len(adj.reason) > 0

    def test_model_version_increments(self):
        self._populate()
        adj, _ = self.engine.suggest_weight_adjustment()
        old = self.engine.model_version
        self.engine.apply_weight_adjustment(adj)
        old_num = float(old.replace("v", ""))
        new_num = float(self.engine.model_version.replace("v", ""))
        assert new_num > old_num


class TestExplainability:
    def setup_method(self):
        self.engine = AdaptiveLearningEngine()

    def test_explain_no_pattern(self):
        explanation = self.engine.explain_weight_calculation("unknown", "unknown")
        assert "default" in explanation["explanation"].lower()
        assert explanation["historical_weight"] == 0.5

    def test_explain_with_pattern(self):
        for i in range(5):
            req = RecordLearningRequest(
                vulnerability_id=f"vuln-{uuid4().hex[:8]}",
                patch_id=f"patch-{uuid4().hex[:8]}",
                vulnerability_type="xss",
                patch_strategy="escaping",
                validation_features={},
                confidence_score=0.85,
                developer_decision=ApprovalDecision.APPROVED,
                developer_id="dev-1",
            )
            self.engine.record_learning_event(req)
        self.engine.extract_patterns()
        explanation = self.engine.explain_weight_calculation("xss", "escaping")
        assert "trust_factor" in explanation["components"]
        assert "acceptance_rate" in explanation["components"]
        assert explanation["historical_weight"] > 0.5

    def test_explain_formula_present(self):
        explanation = self.engine.explain_weight_calculation("unknown", "unknown")
        assert "formula" in explanation

    def test_explain_components_structure(self):
        for i in range(5):
            req = RecordLearningRequest(
                vulnerability_id=f"vuln-{uuid4().hex[:8]}",
                patch_id=f"patch-{uuid4().hex[:8]}",
                vulnerability_type="sql_injection",
                patch_strategy="parameterized_queries",
                validation_features={},
                confidence_score=0.9,
                developer_decision=ApprovalDecision.APPROVED,
                developer_id="dev-1",
            )
            self.engine.record_learning_event(req)
        self.engine.extract_patterns()
        explanation = self.engine.explain_weight_calculation("sql_injection", "parameterized_queries")
        components = explanation["components"]
        assert "sample_count" in components
        assert "trust_factor" in components
        assert "observed_rate" in components
        assert "prior" in components
        assert "confidence_interval" in components
        assert len(components["confidence_interval"]) == 2


class TestSummary:
    def setup_method(self):
        self.engine = AdaptiveLearningEngine()

    def test_empty_summary(self):
        summary = self.engine.get_summary()
        assert summary.total_records == 0
        assert summary.total_patterns == 0

    def test_populated_summary(self):
        for i in range(3):
            req = RecordLearningRequest(
                vulnerability_id=f"vuln-{uuid4().hex[:8]}",
                patch_id=f"patch-{uuid4().hex[:8]}",
                vulnerability_type="xss",
                patch_strategy="escaping",
                validation_features={},
                confidence_score=0.8,
                developer_decision=ApprovalDecision.APPROVED,
                developer_id="dev-1",
            )
            self.engine.record_learning_event(req)
        summary = self.engine.get_summary()
        assert summary.total_records == 3
        assert summary.model_version == MODEL_VERSION

    def test_summary_acceptance_rate(self):
        for i in range(4):
            dec = ApprovalDecision.APPROVED if i < 3 else ApprovalDecision.REJECTED
            req = RecordLearningRequest(
                vulnerability_id=f"vuln-{uuid4().hex[:8]}",
                patch_id=f"patch-{uuid4().hex[:8]}",
                vulnerability_type="xss",
                patch_strategy="escaping",
                validation_features={},
                confidence_score=0.8,
                developer_decision=dec,
                developer_id="dev-1",
            )
            self.engine.record_learning_event(req)
        summary = self.engine.get_summary()
        assert summary.overall_acceptance_rate == 0.75

    def test_summary_includes_patterns(self):
        for i in range(3):
            req = RecordLearningRequest(
                vulnerability_id=f"vuln-{uuid4().hex[:8]}",
                patch_id=f"patch-{uuid4().hex[:8]}",
                vulnerability_type="xss",
                patch_strategy="escaping",
                validation_features={},
                confidence_score=0.8,
                developer_decision=ApprovalDecision.APPROVED,
                developer_id="dev-1",
            )
            self.engine.record_learning_event(req)
        summary = self.engine.get_summary()
        assert summary.total_patterns >= 1


class TestGetRecords:
    def setup_method(self):
        self.engine = AdaptiveLearningEngine()

    def test_get_all_records(self):
        for i in range(3):
            req = RecordLearningRequest(
                vulnerability_id=f"vuln-{uuid4().hex[:8]}",
                patch_id=f"patch-{uuid4().hex[:8]}",
                vulnerability_type="xss",
                patch_strategy="escaping",
                validation_features={},
                confidence_score=0.8,
                developer_decision=ApprovalDecision.APPROVED,
                developer_id="dev-1",
            )
            self.engine.record_learning_event(req)
        records = self.engine.get_records()
        assert len(records) == 3

    def test_filter_by_vuln_type(self):
        for i in range(2):
            req = RecordLearningRequest(
                vulnerability_id=f"vuln-{uuid4().hex[:8]}",
                patch_id=f"patch-{uuid4().hex[:8]}",
                vulnerability_type="xss",
                patch_strategy="escaping",
                validation_features={},
                confidence_score=0.8,
                developer_decision=ApprovalDecision.APPROVED,
                developer_id="dev-1",
            )
            self.engine.record_learning_event(req)
        req2 = RecordLearningRequest(
            vulnerability_id=f"vuln-{uuid4().hex[:8]}",
            patch_id=f"patch-{uuid4().hex[:8]}",
            vulnerability_type="sql_injection",
            patch_strategy="parameterized_queries",
            validation_features={},
            confidence_score=0.9,
            developer_decision=ApprovalDecision.APPROVED,
            developer_id="dev-1",
        )
        self.engine.record_learning_event(req2)
        records = self.engine.get_records(vulnerability_type="xss")
        assert len(records) == 2

    def test_filter_by_strategy(self):
        req = RecordLearningRequest(
            vulnerability_id=f"vuln-{uuid4().hex[:8]}",
            patch_id=f"patch-{uuid4().hex[:8]}",
            vulnerability_type="xss",
            patch_strategy="escaping",
            validation_features={},
            confidence_score=0.8,
            developer_decision=ApprovalDecision.APPROVED,
            developer_id="dev-1",
        )
        self.engine.record_learning_event(req)
        records = self.engine.get_records(patch_strategy="escaping")
        assert len(records) == 1
