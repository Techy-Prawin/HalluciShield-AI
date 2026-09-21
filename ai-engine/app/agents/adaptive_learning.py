"""
Adaptive Learning Engine for HalluciShield AI.

Uses historical developer feedback and validation outcomes to improve
future patch ranking. Implements interpretable pattern-based learning
with full audit trail and versioned scoring.

Design principles:
1. Explainable: Every weight change is traceable to specific patterns
2. Reproducible: Same data always produces same patterns
3. Auditable: All weight adjustments are recorded with reasons
4. Versioned: Model/scoring version changes are explicit
5. Pattern-based: Learns "SQL Injection + Parameterized queries = high success"
"""

import logging
import math
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from app.agents.models import (
    ApprovalDecision,
    DeploymentOutcome,
    LearningDashboard,
    LearningPattern,
    LearningRecord,
    LearningSummary,
    RecordDeploymentOutcomeRequest,
    RecordLearningRequest,
    WeightAdjustment,
    WeightConfig,
)

logger = logging.getLogger(__name__)

MODEL_VERSION = "v2.0"
MIN_SAMPLES_FOR_PATTERN = 3
WILSON_Z = 1.96


def _wilson_score_interval(successes, total, z=WILSON_Z):
    if total == 0:
        return (0.0, 1.0)
    p = successes / total
    denom = 1 + z * z / total
    centre = p + z * z / (2 * total)
    spread = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total)
    lower = max(0.0, (centre - spread) / denom)
    upper = min(1.0, (centre + spread) / denom)
    return (lower, upper)


def _calculate_historical_weight(acceptance_rate, deployment_success_rate, sample_count):
    trust = sample_count / (sample_count + 10)
    observed = 0.6 * acceptance_rate + 0.4 * deployment_success_rate
    weight = trust * observed + (1 - trust) * 0.5
    return max(0.0, min(1.0, weight))


class AdaptiveLearningEngine:

    def __init__(self):
        self._records = []
        self._patterns = {}
        self._adjustments = []
        self._model_version = MODEL_VERSION

    @property
    def model_version(self):
        return self._model_version

    def record_learning_event(self, request):
        record = LearningRecord(
            id="lrn-" + uuid.uuid4().hex[:12],
            vulnerability_id=request.vulnerability_id,
            patch_id=request.patch_id,
            vulnerability_type=request.vulnerability_type,
            patch_strategy=request.patch_strategy,
            validation_features=request.validation_features,
            confidence_score=request.confidence_score,
            developer_decision=request.developer_decision,
            developer_id=request.developer_id,
            rejection_reason=request.rejection_reason,
            deployment_outcome=request.deployment_outcome,
            deployment_notes=request.deployment_notes,
            model_version=self._model_version,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._records.append(record)
        return record

    def record_deployment_outcome(self, request):
        for record in reversed(self._records):
            if (record.vulnerability_id == request.vulnerability_id
                    and record.patch_id == request.patch_id):
                record.deployment_outcome = request.deployment_outcome
                record.deployment_notes = request.deployment_notes
                return record
        return None

    def extract_patterns(self):
        groups = defaultdict(list)
        for record in self._records:
            if record.vulnerability_type and record.patch_strategy:
                key = record.vulnerability_type + ":" + record.patch_strategy
                groups[key].append(record)

        patterns = []
        for key, records in groups.items():
            vuln_type, strategy = key.split(":", 1)
            total = len(records)
            accepted = sum(1 for r in records if r.developer_decision == ApprovalDecision.APPROVED)
            dep_success = sum(1 for r in records if r.deployment_outcome == DeploymentOutcome.SUCCESS)
            dep_known = sum(1 for r in records if r.deployment_outcome != DeploymentOutcome.UNKNOWN)

            acceptance_rate = accepted / total if total > 0 else 0.0
            dep_rate = dep_success / dep_known if dep_known > 0 else 0.5
            avg_conf = sum(r.confidence_score for r in records) / total if total > 0 else 0.0

            hw = _calculate_historical_weight(acceptance_rate, dep_rate, total)
            ci_lo, ci_hi = _wilson_score_interval(accepted, total)

            pattern = LearningPattern(
                pattern_id="pat-" + uuid.uuid4().hex[:12],
                vulnerability_type=vuln_type,
                patch_strategy=strategy,
                sample_count=total,
                acceptance_rate=round(acceptance_rate, 4),
                average_confidence=round(avg_conf, 2),
                deployment_success_rate=round(dep_rate, 4),
                historical_weight=round(hw, 4),
                confidence_interval_lower=round(ci_lo, 4),
                confidence_interval_upper=round(ci_hi, 4),
                last_updated=datetime.now(timezone.utc).isoformat(),
                model_version=self._model_version,
            )
            patterns.append(pattern)
            self._patterns[key] = pattern

        patterns.sort(key=lambda p: p.sample_count, reverse=True)
        return patterns

    def get_historical_weight(self, vulnerability_type, patch_strategy):
        key = vulnerability_type + ":" + patch_strategy
        if key in self._patterns:
            return self._patterns[key].historical_weight
        self.extract_patterns()
        if key in self._patterns:
            return self._patterns[key].historical_weight
        return 0.5

    def get_pattern(self, vulnerability_type, patch_strategy):
        key = vulnerability_type + ":" + patch_strategy
        return self._patterns.get(key)

    def get_patterns_for_vulnerability(self, vulnerability_type):
        self.extract_patterns()
        return [p for p in self._patterns.values() if p.vulnerability_type == vulnerability_type]

    def get_all_patterns(self):
        self.extract_patterns()
        return sorted(self._patterns.values(), key=lambda p: p.sample_count, reverse=True)

    def get_summary(self):
        self.extract_patterns()
        total_records = len(self._records)
        total_patterns = len(self._patterns)
        dep_success = sum(1 for r in self._records if r.deployment_outcome == DeploymentOutcome.SUCCESS)
        dep_known = sum(1 for r in self._records if r.deployment_outcome != DeploymentOutcome.UNKNOWN)
        overall_dep = dep_success / dep_known if dep_known > 0 else 0.0
        accepted = sum(1 for r in self._records if r.developer_decision == ApprovalDecision.APPROVED)
        overall_acc = accepted / total_records if total_records > 0 else 0.0
        return LearningDashboard(
            total_records=total_records,
            total_patterns=total_patterns,
            model_version=self._model_version,
            overall_acceptance_rate=round(overall_acc, 4),
            overall_deployment_success=round(overall_dep, 4),
            patterns=list(self._patterns.values()),
            recent_adjustments=self._adjustments[-10:],
        )

    def suggest_weight_adjustment(self, current_weights=None):
        if not self._patterns:
            self.extract_patterns()
        if not self._patterns:
            return None, "No patterns available for weight adjustment"

        high_success = [
            p for p in self._patterns.values()
            if p.sample_count >= MIN_SAMPLES_FOR_PATTERN and p.acceptance_rate >= 0.7
        ]
        low_success = [
            p for p in self._patterns.values()
            if p.sample_count >= MIN_SAMPLES_FOR_PATTERN and p.acceptance_rate < 0.4
        ]

        if not high_success and not low_success:
            return None, "Not enough reliable patterns for weight adjustment"

        prev = current_weights or WeightConfig()
        new = WeightConfig(
            static_security=prev.static_security,
            unit_test_success=prev.unit_test_success,
            regression_success=prev.regression_success,
            compilation_success=prev.compilation_success,
            performance=prev.performance,
            historical_success=prev.historical_success,
        )

        if high_success:
            boost = min(0.05, len(high_success) * 0.01)
            new.historical_success = min(0.30, new.historical_success + boost)
        if low_success and not high_success:
            reduction = min(0.03, len(low_success) * 0.005)
            new.historical_success = max(0.05, new.historical_success - reduction)

        total = new.sum_weights()
        if abs(total - 1.0) > 0.01:
            new.historical_success += (1.0 - total)

        pattern_ids = [p.pattern_id for p in high_success + low_success]
        adj = WeightAdjustment(
            adjustment_id="adj-" + uuid.uuid4().hex[:12],
            previous_weights=prev,
            new_weights=new,
            reason="Auto-suggested based on {} high-success and {} low-success patterns".format(
                len(high_success), len(low_success)
            ),
            patterns_used=pattern_ids,
            model_version=self._model_version,
            adjusted_by="system",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._adjustments.append(adj)
        return adj, "Weight adjustment suggested"

    def apply_weight_adjustment(self, adjustment):
        self._adjustments.append(adjustment)
        old_ver = float(self._model_version.replace("v", ""))
        self._model_version = "v{:.1f}".format(old_ver + 0.1)

    def get_adjustment_history(self):
        return list(self._adjustments)

    def get_records(self, vulnerability_type=None, patch_strategy=None):
        records = self._records
        if vulnerability_type:
            records = [r for r in records if r.vulnerability_type == vulnerability_type]
        if patch_strategy:
            records = [r for r in records if r.patch_strategy == patch_strategy]
        return records

    def explain_weight_calculation(self, vulnerability_type, patch_strategy):
        key = vulnerability_type + ":" + patch_strategy
        pattern = self._patterns.get(key)
        if not pattern:
            self.extract_patterns()
            pattern = self._patterns.get(key)
        if not pattern:
            return {
                "vulnerability_type": vulnerability_type,
                "patch_strategy": patch_strategy,
                "explanation": "No pattern found. Using default weight 0.5",
                "historical_weight": 0.5,
                "formula": "weight = 0.5 (default prior)",
                "components": {},
            }

        trust = pattern.sample_count / (pattern.sample_count + 10)
        observed = 0.6 * pattern.acceptance_rate + 0.4 * pattern.deployment_success_rate
        return {
            "vulnerability_type": vulnerability_type,
            "patch_strategy": patch_strategy,
            "explanation": (
                "weight = trust_factor * observed_rate + (1-trust_factor) * prior"
                " where trust_factor = samples/(samples+10) = {:.4f}"
                ", observed_rate = 0.6*acceptance + 0.4*deployment = {:.4f}"
                ", prior = 0.5"
            ).format(trust, observed),
            "historical_weight": pattern.historical_weight,
            "formula": "trust_factor * (0.6 * acceptance_rate + 0.4 * deployment_rate) + (1 - trust_factor) * 0.5",
            "components": {
                "sample_count": pattern.sample_count,
                "trust_factor": round(trust, 4),
                "acceptance_rate": pattern.acceptance_rate,
                "deployment_success_rate": pattern.deployment_success_rate,
                "observed_rate": round(observed, 4),
                "prior": 0.5,
                "confidence_interval": [pattern.confidence_interval_lower, pattern.confidence_interval_upper],
            },
        }
