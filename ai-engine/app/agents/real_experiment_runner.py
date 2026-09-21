"""
Real experiment runner for HalluciShield research.

Executes the actual HalluciShield pipeline for each benchmark test case:
  1. Creates a temporary workspace with the vulnerable code
  2. Runs the real Security Analysis Agent (Semgrep or fallback scanner)
  3. Runs the real Hallucination Detection Agent (if applicable)
  4. Runs the real Dependency Analysis Agent (if applicable)
  5. Runs the real Patch Generation Agent (generates 5 candidates)
  6. Calculates actual confidence scores
  7. Records full provenance with data_source = "real_execution"

DOES NOT use any _simulate_* functions.
"""

import logging
import os
import platform
import shutil
import tempfile
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.agents.models import (
    ExperimentConfig,
    ExperimentDataSource,
    ExperimentMetrics,
    ExperimentMode,
    ExperimentRun,
    PatchGenerationRequest,
    TestCase,
    TestCaseRecord,
    VulnerabilityTestCategory,
)
from app.agents.real_benchmark_dataset import (
    REAL_BENCHMARK_BY_CATEGORY,
    REAL_BENCHMARK_BY_ID,
    REAL_BENCHMARK_CASES,
    REAL_BENCHMARK_VERSION,
)
from app.agents.test_dataset import DATASET_VERSION  # noqa: F401


def _compute_dataset_hash(test_cases: list) -> str:
    """Compute a deterministic hash for a set of test cases."""
    import hashlib
    content = "".join(tc.test_id for tc in sorted(test_cases, key=lambda t: t.test_id))
    return hashlib.sha256(content.encode()).hexdigest()[:16]

logger = logging.getLogger(__name__)


def _create_workspace(test_case: TestCase) -> str:
    """Create a temporary workspace directory with the vulnerable code file."""
    tmp_dir = tempfile.mkdtemp(prefix=f"hs_real_{test_case.test_id}_")

    # Determine file extension from file_path
    file_name = test_case.file_path
    if not os.path.splitext(file_name)[1]:
        file_name += ".py"

    # For text files (requirements.txt etc.), write directly
    # For Python files, write as-is
    file_path = os.path.join(tmp_dir, file_name)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(test_case.original_code)

    return tmp_dir


def _run_security_detection(
    workspace_path: str,
    test_case: TestCase,
) -> Dict:
    """
    Run the real Security Analysis Agent on the workspace.
    Returns detection results.
    """
    from app.agents.security_agent import SecurityAnalysisAgent

    agent = SecurityAnalysisAgent()
    try:
        response = agent.analyze_security(
            repository_id=f"benchmark-{test_case.test_id}",
            workspace_path=workspace_path,
        )
        findings = response.findings
        detected = len(findings) > 0
        finding_types = [f.type.value for f in findings]
        finding_summary = "; ".join(finding_types[:5]) if finding_types else "none"
        return {
            "detected": detected,
            "finding_count": response.total_vulnerabilities,
            "critical_count": response.critical_count,
            "high_count": response.high_count,
            "medium_count": response.medium_count,
            "finding_types": finding_types,
            "summary": finding_summary,
        }
    except Exception as e:
        logger.warning(f"[RealExperiment] Security detection failed for {test_case.test_id}: {e}")
        return {
            "detected": False,
            "finding_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "finding_types": [],
            "summary": f"detection_error: {e}",
        }


def _run_hallucination_detection(
    workspace_path: str,
    test_case: TestCase,
) -> Dict:
    """
    Run the real Hallucination Detection Agent on the workspace.
    """
    from app.agents.hallucination_agent import HallucinationDetectionAgent

    agent = HallucinationDetectionAgent()
    try:
        response = agent.detect_hallucinations(
            repository_id=f"benchmark-{test_case.test_id}",
            workspace_path=workspace_path,
        )
        findings = response.findings
        detected = len(findings) > 0
        finding_summary = "; ".join(
            f"{f.package_name}({f.finding_type})" for f in findings[:5]
        ) if findings else "none"
        return {
            "detected": detected,
            "finding_count": len(findings),
            "summary": finding_summary,
        }
    except Exception as e:
        logger.warning(f"[RealExperiment] Hallucination detection failed for {test_case.test_id}: {e}")
        return {
            "detected": False,
            "finding_count": 0,
            "summary": f"detection_error: {e}",
        }


def _run_dependency_analysis(
    workspace_path: str,
    test_case: TestCase,
) -> Dict:
    """
    Run the real Dependency Analysis Agent on the workspace.
    """
    from app.agents.dependency_agent import DependencyAnalysisAgent

    agent = DependencyAnalysisAgent()
    try:
        response = agent.analyze_dependencies(
            repository_id=f"benchmark-{test_case.test_id}",
            workspace_path=workspace_path,
        )
        findings = response.findings
        detected = len(findings) > 0
        finding_summary = "; ".join(
            f"{f.package_name}({f.type.value})" for f in findings[:5]
        ) if findings else "none"
        return {
            "detected": detected,
            "finding_count": len(findings),
            "summary": finding_summary,
        }
    except Exception as e:
        logger.warning(f"[RealExperiment] Dependency analysis failed for {test_case.test_id}: {e}")
        return {
            "detected": False,
            "finding_count": 0,
            "summary": f"detection_error: {e}",
        }


def _run_patch_generation(
    test_case: TestCase,
    workspace_path: str,
) -> Dict:
    """
    Run the real Patch Generation Agent on the vulnerable code.
    Returns full PatchCandidate objects for downstream validation.
    """
    from app.agents.patch_agent import PatchGenerationAgent

    agent = PatchGenerationAgent()
    try:
        request = PatchGenerationRequest(
            vulnerability_id=f"bench-{test_case.test_id}",
            vulnerability_type=test_case.vulnerability_type,
            severity=test_case.severity,
            file=test_case.file_path,
            line=test_case.vulnerable_line,
            vulnerable_code=test_case.original_code,
            surrounding_code="",
            description=test_case.description,
            cwe=test_case.cwe,
        )
        response = agent.generate_patches(request)
        candidates = response.candidates
        applicable = [c for c in candidates if not c.is_not_applicable]
        not_applicable = [c for c in candidates if c.is_not_applicable]

        return {
            "patch_count": len(candidates),
            "candidates": candidates,
            "applicable_candidates": applicable,
            "not_applicable_candidates": not_applicable,
            "model_used": response.model_used,
            "duration_ms": response.generation_duration_ms,
        }
    except Exception as e:
        logger.warning(f"[RealExperiment] Patch generation failed for {test_case.test_id}: {e}")
        return {
            "patch_count": 0,
            "candidates": [],
            "applicable_candidates": [],
            "not_applicable_candidates": [],
            "model_used": "error",
            "duration_ms": 0,
        }


def _validate_patches(
    test_case: TestCase,
    workspace_path: str,
    candidates: List,
) -> List[Dict]:
    """
    Run ValidationAgent.validate_candidate() for each applicable patch in isolated temp dirs.
    Returns list of validation results with per-patch scores.
    """
    from app.agents.models import ValidateCandidatesRequest
    from app.agents.validation_agent import ValidationAgent

    if not candidates:
        return []

    agent = ValidationAgent()
    results = []

    for candidate in candidates:
        if candidate.is_not_applicable:
            results.append({
                "patch_id": candidate.patch_id,
                "is_not_applicable": True,
                "validation_status": "NOT_APPLICABLE",
                "scores": {},
            })
            continue

        try:
            request = ValidateCandidatesRequest(
                vulnerability_id=f"bench-{test_case.test_id}",
                candidates=[candidate],
                file_path=test_case.file_path,
                original_code=test_case.original_code,
                language="python",
                compile_command="python -m py_compile test.py",
            )
            validation_result = agent.validate_candidate(candidate, request)

            results.append({
                "patch_id": candidate.patch_id,
                "is_not_applicable": False,
                "validation_status": validation_result.validation_status.value,
                "scores": {
                    "compilation": validation_result.compilation_score.score,
                    "unit_test": validation_result.unit_test_score.score,
                    "regression": validation_result.regression_score.score,
                    "security": validation_result.security_score.score,
                    "functional": validation_result.functional_score.score,
                    "performance": validation_result.performance_score.score,
                },
                "validation_result": validation_result,
            })
        except Exception as e:
            logger.warning(f"[RealExperiment] Validation failed for {candidate.patch_id}: {e}")
            results.append({
                "patch_id": candidate.patch_id,
                "is_not_applicable": False,
                "validation_status": "ERROR",
                "scores": {},
            })

    return results


def _calculate_real_confidence(
    detection_result: Dict,
    patch_result: Dict,
    test_case: TestCase,
    validation_results: List[Dict] = None,
) -> float:
    """
    Calculate an actual confidence score using the real ConfidenceEngine.
    Uses real validation results when available.
    """
    from app.agents.confidence_engine import ConfidenceEngine

    if patch_result["patch_count"] == 0:
        return 0.0

    candidates = patch_result.get("applicable_candidates", [])
    if not candidates:
        return 0.0

    best_confidence = 0.0

    for i, candidate in enumerate(candidates):
        vr_result = None
        if validation_results:
            for vr in validation_results:
                if vr.get("patch_id") == candidate.patch_id and not vr.get("is_not_applicable"):
                    vr_result = vr.get("validation_result")
                    break

        if vr_result is None:
            continue

        engine = ConfidenceEngine()
        cr = engine.calculate_confidence(vr_result, historical_success_rate=0.5)

        if cr.confidence_score > best_confidence:
            best_confidence = cr.confidence_score

    return best_confidence


def _rank_patches(
    candidates: List,
    validation_results: List[Dict],
    best_confidence: float,
) -> List[Dict]:
    """
    Rank patches by confidence, exclude FAIL/NOT_APPLICABLE from recommendations.
    Returns list of ranked patches with confidence scores.
    """
    from app.agents.confidence_engine import ConfidenceEngine

    ranked = []
    for candidate in candidates:
        vr = None
        for v in validation_results:
            if v.get("patch_id") == candidate.patch_id:
                vr = v
                break

        if vr is None or vr.get("is_not_applicable"):
            continue

        if vr.get("validation_status") == "FAIL":
            continue

        validation_result = vr.get("validation_result")
        if validation_result is None:
            continue

        engine = ConfidenceEngine()
        cr = engine.calculate_confidence(validation_result, historical_success_rate=0.5)

        ranked.append({
            "patch_id": candidate.patch_id,
            "security_strategy": candidate.security_strategy,
            "confidence_score": cr.confidence_score,
            "validation_status": vr.get("validation_status"),
            "meets_safety_threshold": cr.confidence_score >= 50.0,
        })

    ranked.sort(key=lambda x: x["confidence_score"], reverse=True)
    return ranked


def _is_code_vuln_category(cat: VulnerabilityTestCategory) -> bool:
    """Check if this category is best detected by the security scanner."""
    return cat in (
        VulnerabilityTestCategory.SQL_INJECTION,
        VulnerabilityTestCategory.XSS,
        VulnerabilityTestCategory.HARDCODED_SECRETS,
        VulnerabilityTestCategory.COMMAND_INJECTION,
        VulnerabilityTestCategory.PATH_TRAVERSAL,
        VulnerabilityTestCategory.INSECURE_JWT,
    )


def _is_hallucination_category(cat: VulnerabilityTestCategory) -> bool:
    """Check if this category is best detected by hallucination agent."""
    return cat in (
        VulnerabilityTestCategory.HALLUCINATED_API,
    )


def _is_dependency_category(cat: VulnerabilityTestCategory) -> bool:
    """Check if this category is best detected by dependency agent."""
    return cat in (
        VulnerabilityTestCategory.HALLUCINATED_PACKAGE,
    )


def run_real_experiment(
    config: ExperimentConfig,
    modes: List[ExperimentMode],
) -> ExperimentRun:
    """
    Run a REAL experiment using the actual HalluciShield pipeline.

    For each test case:
    1. Creates a temporary workspace with vulnerable code
    2. Runs real detection agents
    3. Generates real patches
    4. Calculates real confidence
    5. Records provenance with data_source = "real_execution"

    This function does NOT use any _simulate_* functions.
    """
    experiment_id = f"EXP-REAL-{uuid.uuid4().hex[:8].upper()}"
    started_at = datetime.now(timezone.utc).isoformat()
    start_ms = time.time() * 1000

    test_cases = list(REAL_BENCHMARK_CASES)
    if config.test_categories:
        test_cases = [
            tc for tc in test_cases
            if tc.vuln_category in config.test_categories
        ]

    system_config = {
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "dataset_version": REAL_BENCHMARK_VERSION,
        "experiment_mode": "REAL",
    }

    records: List[TestCaseRecord] = []
    workspace_dirs: List[str] = []

    for mode in modes:
        for tc in test_cases:
            case_start_ms = time.time() * 1000
            workspace_path = None

            try:
                # Step 1: Create workspace
                workspace_path = _create_workspace(tc)
                workspace_dirs.append(workspace_path)

                # Step 2: Run appropriate detection
                detection_result = {"detected": False, "finding_count": 0, "summary": "not_run"}

                if mode in (ExperimentMode.HALLUCISHIELD, ExperimentMode.STATIC_SCANNER):
                    if _is_code_vuln_category(tc.vuln_category):
                        detection_result = _run_security_detection(workspace_path, tc)
                    elif _is_hallucination_category(tc.vuln_category):
                        detection_result = _run_hallucination_detection(workspace_path, tc)
                    elif _is_dependency_category(tc.vuln_category):
                        detection_result = _run_dependency_analysis(workspace_path, tc)
                    elif tc.vuln_category == VulnerabilityTestCategory.AUTH_FLAW:
                        # Auth flaws: security scanner won't find it (no regex pattern)
                        # This is a known false negative - record as such
                        detection_result = _run_security_detection(workspace_path, tc)
                        detection_result["known_false_negative"] = True
                        detection_result["false_negative_reason"] = (
                            "Security scanner lacks regex pattern for authentication flaws. "
                            "This is a known limitation documented in research."
                        )

                elif mode in (ExperimentMode.LLM_ONLY, ExperimentMode.SINGLE_PATCH_LLM,
                              ExperimentMode.MULTI_PATCH_LLM):
                    if _is_hallucination_category(tc.vuln_category):
                        detection_result = _run_hallucination_detection(workspace_path, tc)
                    elif _is_dependency_category(tc.vuln_category):
                        detection_result = _run_dependency_analysis(workspace_path, tc)

                elif mode == ExperimentMode.MULTI_PATCH_VALIDATION:
                    if _is_code_vuln_category(tc.vuln_category):
                        detection_result = _run_security_detection(workspace_path, tc)
                    elif _is_hallucination_category(tc.vuln_category):
                        detection_result = _run_hallucination_detection(workspace_path, tc)
                    elif _is_dependency_category(tc.vuln_category):
                        detection_result = _run_dependency_analysis(workspace_path, tc)

                # Step 3: Generate patches (for patch-capable modes)
                patch_result = {"patch_count": 0, "patch_ids": [], "model_used": "none", "duration_ms": 0}
                validation_results = []
                if mode in (ExperimentMode.HALLUCISHIELD, ExperimentMode.MULTI_PATCH_VALIDATION,
                            ExperimentMode.MULTI_PATCH_LLM):
                    patch_result = _run_patch_generation(tc, workspace_path)

                elif mode == ExperimentMode.SINGLE_PATCH_LLM:
                    pr = _run_patch_generation(tc, workspace_path)
                    if pr["patch_count"] > 0:
                        patch_result = {
                            **pr,
                            "patch_count": 1,
                            "candidates": pr["candidates"][:1],
                            "applicable_candidates": pr["applicable_candidates"][:1],
                        }

                # Step 4: Validate patches (if any applicable candidates)
                applicable = patch_result.get("applicable_candidates", [])
                if applicable:
                    validation_results = _validate_patches(tc, workspace_path, applicable)

                # Step 5: Calculate confidence using real validation results
                confidence = _calculate_real_confidence(
                    detection_result, patch_result, tc, validation_results
                )

                # Step 6: Rank patches by confidence (exclude FAIL/NOT_APPLICABLE)
                ranked_patches = []
                if validation_results:
                    ranked_patches = _rank_patches(
                        patch_result.get("candidates", []),
                        validation_results,
                        confidence,
                    )

                # Step 7: Determine correctness
                detected = detection_result["detected"]
                detection_correct = detected == tc.expected_detection
                false_positive = detected and not tc.expected_detection
                false_negative = not detected and tc.expected_detection
                patch_success = detected and confidence > 50.0

                case_duration_ms = int(time.time() * 1000 - case_start_ms)

                # Extract validation summary
                validation_summary = []
                for vr in validation_results:
                    if not vr.get("is_not_applicable"):
                        validation_summary.append({
                            "patch_id": vr["patch_id"],
                            "status": vr["validation_status"],
                            "scores": vr.get("scores", {}),
                        })

                record = TestCaseRecord(
                    test_id=tc.test_id,
                    vuln_category=tc.vuln_category,
                    vulnerability_type=tc.vulnerability_type,
                    mode=mode,
                    data_source=ExperimentDataSource.REAL,
                    detection_result=detected,
                    detection_correct=detection_correct,
                    generated_patches_count=patch_result["patch_count"],
                    validation_performed=len(validation_results) > 0,
                    best_confidence_score=confidence,
                    selected_patch_id=ranked_patches[0]["patch_id"] if ranked_patches else "",
                    patch_success=patch_success,
                    regression_detected=False,
                    validation_time_ms=patch_result["duration_ms"],
                    false_positive=false_positive,
                    false_negative=false_negative,
                    actual_scanner_result=detection_result["summary"],
                    actual_patches=[c.security_strategy for c in patch_result.get("candidates", [])],
                    actual_validation_status=validation_summary[0]["status"] if validation_summary else "SKIPPED",
                    actual_patch_outcome="validated" if validation_summary else "no_patches",
                    execution_time_ms=case_duration_ms,
                    system_config=system_config,
                    experiment_version=REAL_BENCHMARK_VERSION,
                    metadata={
                        "dataset_version": REAL_BENCHMARK_VERSION,
                        "severity": tc.severity,
                        "cwe": tc.cwe,
                        "detection_finding_count": detection_result["finding_count"],
                        "patch_model_used": patch_result.get("model_used", "none"),
                        "validation_results": validation_summary,
                        "ranked_patches": ranked_patches,
                        "applicable_count": len(patch_result.get("applicable_candidates", [])),
                        "not_applicable_count": len(patch_result.get("not_applicable_candidates", [])),
                        "known_false_negative": detection_result.get("known_false_negative", False),
                        "false_negative_reason": detection_result.get("false_negative_reason", ""),
                    },
                )
                records.append(record)

                logger.info(
                    f"[RealExperiment] {tc.test_id} / {mode.value}: "
                    f"detected={detected}, patches={patch_result['patch_count']}, "
                    f"confidence={confidence:.1f} ({case_duration_ms}ms)"
                )

            except Exception as e:
                logger.error(f"[RealExperiment] Failed on {tc.test_id}/{mode.value}: {e}")
                records.append(TestCaseRecord(
                    test_id=tc.test_id,
                    vuln_category=tc.vuln_category,
                    vulnerability_type=tc.vulnerability_type,
                    mode=mode,
                    data_source=ExperimentDataSource.REAL,
                    detection_result=False,
                    detection_correct=False,
                    metadata={"error": str(e)},
                ))

    # Cleanup temp directories
    for d in workspace_dirs:
        try:
            shutil.rmtree(d, ignore_errors=True)
        except Exception:
            pass

    # Compute metrics
    metrics_by_mode = {}
    for mode in modes:
        metrics_by_mode[mode.value] = _compute_real_metrics(mode, records)

    completed_at = datetime.now(timezone.utc).isoformat()
    duration_ms = int(time.time() * 1000 - start_ms)

    run = ExperimentRun(
        experiment_id=experiment_id,
        config=config,
        data_source=ExperimentDataSource.REAL,
        records=records,
        metrics_by_mode=metrics_by_mode,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=duration_ms,
        dataset_hash=_compute_dataset_hash(test_cases),
        status="completed",
    )

    logger.info(
        f"[RealExperiment] Completed {experiment_id}: "
        f"{len(records)} records across {len(modes)} modes in {duration_ms}ms"
    )
    return run


def _compute_real_metrics(
    mode: ExperimentMode,
    records: List[TestCaseRecord],
) -> ExperimentMetrics:
    """Compute metrics from real experiment records."""
    mode_records = [r for r in records if r.mode == mode]
    tp = sum(1 for r in mode_records if r.detection_correct and r.detection_result)
    fp = sum(1 for r in mode_records if r.false_positive)
    fn = sum(1 for r in mode_records if r.false_negative)
    tn = sum(1 for r in mode_records if r.detection_correct and not r.detection_result)

    total = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    total_patches = sum(r.generated_patches_count for r in mode_records)
    validated = sum(1 for r in mode_records if r.validation_performed)
    successes = sum(1 for r in mode_records if r.patch_success)
    regressions = sum(1 for r in mode_records if r.regression_detected)
    patch_success = successes / validated if validated > 0 else 0.0
    regression_rate = regressions / validated if validated > 0 else 0.0

    confidences = [r.best_confidence_score for r in mode_records if r.best_confidence_score > 0]
    avg_conf = sum(confidences) / len(confidences) if confidences else 0.0
    avg_time = (sum(r.execution_time_ms for r in mode_records) / len(mode_records)) if mode_records else 0.0

    return ExperimentMetrics(
        mode=mode,
        total_tests=len(mode_records),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        detection_accuracy=round(accuracy, 4),
        patch_success_rate=round(patch_success, 4),
        regression_rate=round(regression_rate, 4),
        false_positive_rate=round(fpr, 4),
        avg_validation_time_ms=round(avg_time, 1),
        confidence_calibration=round(avg_conf, 4),
        total_patches_generated=total_patches,
        total_patches_validated=validated,
    )
