"""
Multi-Patch Competitive Generation & Evidence-Based Patch Selection for HalluciShield AI.

Implements competitive patch selection using actual validation evidence from:
ValidationAgent -> Security Re-scan -> AECEngine

Compares 3 selection strategies:
- Baseline 1: First generated patch (candidates[0])
- Baseline 2: Best-of-N using standard validation evidence (legacy ACE score)
- Proposed: AECE-based evidence-aware selection (evidence-aware confidence & completeness)

CRITICAL RESEARCH INTEGRITY:
- Never selects using ground truth labels
- Uses strictly real evidence produced by the pipeline
- Missing evidence is marked NOT_AVAILABLE and never fabricated
- Synthetic test fixture results must not be presented as empirical evidence
- real_production mode uses real PatchGenerationAgent, ValidationAgent, SecurityAgent, ACE/AECE
"""

import logging
import time
from typing import List, Dict, Any, Optional

from app.agents.models import (
    PatchCandidate,
    PatchValidationResult,
    ValidateCandidatesRequest,
    CandidateSelectionRecord,
    MultiPatchSelectionResult,
    DecisionEnum,
    AECEResult,
)
from app.agents.validation_agent import ValidationAgent
from app.agents.aece_engine import AECEngine

logger = logging.getLogger(__name__)


class PatchSelector:
    """
    Evaluates candidate patches and selects the optimal patch using
    competitive multi-patch evidence.
    """

    def __init__(
        self,
        validation_agent: Optional[ValidationAgent] = None,
        aece_engine: Optional[AECEngine] = None,
    ):
        self.validation_agent = validation_agent or ValidationAgent()
        self.aece_engine = aece_engine or AECEngine()

    def evaluate_candidates(
        self,
        candidates: List[PatchCandidate],
        validation_request: ValidateCandidatesRequest,
        validation_results: Optional[List[PatchValidationResult]] = None,
        historical_success_rates: Optional[Dict[str, float]] = None,
    ) -> List[CandidateSelectionRecord]:
        """
        Run validation and AECE for each candidate, collecting evidence records.
        """
        start_time = time.time()
        records: List[CandidateSelectionRecord] = []

        # Map validation results if already provided, else run validation
        val_map: Dict[str, PatchValidationResult] = {}
        if validation_results:
            for vr in validation_results:
                val_map[vr.patch_id] = vr
        else:
            for cand in candidates:
                vr = self.validation_agent.validate_candidate(cand, validation_request)
                val_map[cand.patch_id] = vr

        for cand in candidates:
            vr = val_map.get(cand.patch_id)
            if not vr:
                vr = self.validation_agent.validate_candidate(cand, validation_request)

            # Calculate AECE score
            aece: AECEResult = self.aece_engine.calculate_aece(
                validation_result=vr,
                historical_success_rates=historical_success_rates,
                vulnerability_type=getattr(validation_request, "vulnerability_type", None),
            )

            # Summarize security & performance results
            sec_dict = {
                "score": vr.security_score.score if vr.security_score else 0.0,
                "vulnerabilities_found": vr.security_score.vulnerabilities_found if vr.security_score else 0,
                "findings": vr.security_score.findings if vr.security_score else [],
            }
            perf_dict = {
                "score": vr.performance_score.score if vr.performance_score else 0.0,
                "regression_detected": getattr(vr.performance_score, "time_regression_pct", 0.0) > 50.0 if vr.performance_score else False,
            }
            val_dict = {
                "status": vr.validation_status.value if vr.validation_status else "UNKNOWN",
                "compilation_passed": bool(vr.compilation_score.success) if vr.compilation_score else False,
                "unit_tests_passed": bool(vr.unit_test_score.failed == 0 and vr.unit_test_score.passed > 0) if vr.unit_test_score else False,
                "regression_passed": bool(vr.regression_score.regressions_found == 0) if vr.regression_score else False,
            }

            record = CandidateSelectionRecord(
                patch_id=cand.patch_id,
                strategy=getattr(cand, "strategy", None) or getattr(cand, "security_strategy", "unknown"),
                validation_result=val_dict,
                security_result=sec_dict,
                ace_score=aece.legacy_ace_score,
                evidence_completeness=aece.evidence_completeness,
                evidence_aware_confidence=aece.evidence_aware_confidence,
                performance_result=perf_dict,
                final_decision=aece.decision,
                selected=False,
                selection_rationale="",
            )
            records.append(record)

        return records

    def select_best(
        self,
        candidates: List[PatchCandidate],
        validation_request: ValidateCandidatesRequest,
        validation_results: Optional[List[PatchValidationResult]] = None,
        historical_success_rates: Optional[Dict[str, float]] = None,
    ) -> MultiPatchSelectionResult:
        """
        Run competitive evaluation and select patches using Baseline 1,
        Baseline 2, and Proposed AECE.
        """
        start_time = time.time()
        if not candidates:
            raise ValueError("No candidate patches provided for selection.")

        records = self.evaluate_candidates(
            candidates=candidates,
            validation_request=validation_request,
            validation_results=validation_results,
            historical_success_rates=historical_success_rates,
        )

        # Baseline 1: First generated candidate
        baseline_1_id = records[0].patch_id

        # Baseline 2: Best-of-N using legacy ACE score
        # Select candidate with highest legacy_ace_score
        b2_sorted = sorted(records, key=lambda r: r.ace_score, reverse=True)
        baseline_2_id = b2_sorted[0].patch_id

        # Proposed: AECE-based selection
        # Criteria:
        # 1. Non-REJECT decisions prioritized over REJECT/INSUFFICIENT_EVIDENCE
        # 2. Highest evidence_aware_confidence
        # 3. Higher evidence_completeness as tie-breaker
        def proposed_key(r: CandidateSelectionRecord):
            priority = 0
            if r.final_decision == DecisionEnum.AUTO_APPLY.value:
                priority = 3
            elif r.final_decision == DecisionEnum.HUMAN_REVIEW.value:
                priority = 2
            elif r.final_decision == DecisionEnum.INSUFFICIENT_EVIDENCE.value:
                priority = 1
            else:
                priority = 0
            return (priority, r.evidence_aware_confidence, r.evidence_completeness, r.ace_score)

        proposed_sorted = sorted(records, key=proposed_key, reverse=True)
        proposed_id = proposed_sorted[0].patch_id

        # Mark selected candidate
        for r in records:
            if r.patch_id == proposed_id:
                r.selected = True
                r.selection_rationale = (
                    f"Selected by AECE: Decision={r.final_decision}, "
                    f"Confidence={r.evidence_aware_confidence:.1f}%, "
                    f"Completeness={r.evidence_completeness * 100:.1f}%, "
                    f"ACE={r.ace_score:.1f}%"
                )

        duration_ms = int((time.time() - start_time) * 1000)

        return MultiPatchSelectionResult(
            vulnerability_id=validation_request.vulnerability_id,
            total_candidates=len(records),
            baseline_1_selected=baseline_1_id,
            baseline_2_selected=baseline_2_id,
            proposed_selected=proposed_id,
            candidates=records,
            selection_duration_ms=duration_ms,
        )

    def compare_strategies_on_batch(
        self,
        batch_results: List[MultiPatchSelectionResult],
        ground_truth_outcomes: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Compare performance of Baseline 1, Baseline 2, and Proposed across a batch.
        
        Args:
            batch_results: List of MultiPatchSelectionResult for each vulnerability
            ground_truth_outcomes: Optional map of {vulnerability_id: {patch_id: {valid: bool, vuln_removed: bool, regression_free: bool}}}
                                   Used strictly for post-hoc empirical evaluation, NOT selection.
        """
        total = len(batch_results)
        if total == 0:
            return {"error": "Empty batch"}

        def analyze_selection(get_selected_id):
            selected_records: List[CandidateSelectionRecord] = []
            for res in batch_results:
                sel_id = get_selected_id(res)
                rec = next((c for c in res.candidates if c.patch_id == sel_id), res.candidates[0])
                selected_records.append(rec)

            avg_conf = sum(r.evidence_aware_confidence for r in selected_records) / total
            avg_ace = sum(r.ace_score for r in selected_records) / total
            avg_comp = sum(r.evidence_completeness for r in selected_records) / total
            
            compilation_success_count = sum(
                1 for r in selected_records if r.validation_result.get("compilation_passed", False)
            )
            val_success_count = sum(
                1 for r in selected_records if r.validation_result.get("status") in ("PASS", "PASSED")
            )

            metrics = {
                "total_samples": total,
                "avg_confidence": round(avg_conf, 2),
                "avg_ace_score": round(avg_ace, 2),
                "avg_evidence_completeness": round(avg_comp, 3),
                "compilation_success_rate": round(compilation_success_count / total, 4),
                "validation_success_rate": round(val_success_count / total, 4),
            }

            if ground_truth_outcomes:
                valid_count = 0
                vuln_removed_count = 0
                reg_free_count = 0
                fa_count = 0  # Accepted but actually invalid
                fr_count = 0  # Rejected but actually valid

                for res in batch_results:
                    sel_id = get_selected_id(res)
                    rec = next((c for c in res.candidates if c.patch_id == sel_id), res.candidates[0])
                    gt = ground_truth_outcomes.get(res.vulnerability_id, {}).get(sel_id, {})
                    is_valid = gt.get("valid", False)
                    if is_valid:
                        valid_count += 1
                    if gt.get("vuln_removed", False):
                        vuln_removed_count += 1
                    if gt.get("regression_free", False):
                        reg_free_count += 1

                    is_accepted = rec.final_decision in (DecisionEnum.AUTO_APPLY.value, DecisionEnum.HUMAN_REVIEW.value)
                    if is_accepted and not is_valid:
                        fa_count += 1
                    if not is_accepted and is_valid:
                        fr_count += 1

                metrics.update({
                    "ground_truth_valid_rate": round(valid_count / total, 4),
                    "vulnerability_removal_rate": round(vuln_removed_count / total, 4),
                    "regression_preservation_rate": round(reg_free_count / total, 4),
                    "false_acceptance_rate": round(fa_count / total, 4),
                    "false_rejection_rate": round(fr_count / total, 4),
                })

            return metrics

        return {
            "candidate_count_distribution": [len(r.candidates) for r in batch_results],
            "baseline_1_first_patch": analyze_selection(lambda r: r.baseline_1_selected),
            "baseline_2_best_of_n": analyze_selection(lambda r: r.baseline_2_selected),
            "proposed_aece_selection": analyze_selection(lambda r: r.proposed_selected),
        }
