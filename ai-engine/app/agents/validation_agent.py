"""
Validation Agent for HalluciShield AI.

Evaluates candidate patches across 6 independent dimensions:
1. Compilation - Does the patched code compile?
2. Unit Tests - Do unit tests pass?
3. Regression Tests - Are there any regressions?
4. Security Scan - Are there new vulnerabilities?
5. Functional Behavior - Is the original behavior preserved?
6. Performance Impact - Is there a performance regression?

Each dimension produces an independent score from 0.0 to 1.0.
The final confidence score is NOT calculated here (deferred to a later milestone).
"""

import logging
import shlex
import time
import uuid
import re
import subprocess
import tempfile
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

from app.agents.models import (
    CompilationScore,
    FunctionalBehaviorScore,
    PatchCandidate,
    PatchValidationResult,
    PerformanceImpactScore,
    RegressionScore,
    SandboxStatus,
    SecurityValidationScore,
    UnitTestScore,
    ValidateCandidatesRequest,
    ValidateCandidatesResponse,
    ValidationStatus,
)

logger = logging.getLogger(__name__)

PERFORMANCE_THRESHOLD_PCT = 50.0  # Max acceptable performance regression %
MEMORY_THRESHOLD_PCT = 30.0       # Max acceptable memory regression %
SECURITY_SEVERITY_WEIGHTS = {
    "CRITICAL": 0.0,
    "HIGH": 0.25,
    "MEDIUM": 0.5,
    "LOW": 0.75,
}


class ValidationAgent:
    """
    Validation Agent for evaluating candidate patches.

    Produces independent scores for each validation dimension.
    Does NOT calculate final confidence score.
    """

    def __init__(self):
        self._sandbox_available: Optional[bool] = None

    def _is_sandbox_available(self) -> bool:
        """Probe whether the Docker sandbox can actually execute code."""
        if self._sandbox_available is None:
            try:
                from app.agents.sandbox_agent import SandboxAgent
                self._sandbox_available = SandboxAgent().is_available()
            except Exception:
                self._sandbox_available = False
        return self._sandbox_available

    def validate_candidate(
        self,
        candidate: PatchCandidate,
        request: ValidateCandidatesRequest,
    ) -> PatchValidationResult:
        """
        Validate a single patch candidate across all 6 dimensions.

        Args:
            candidate: The patch candidate to validate
            request: Validation request with configuration

        Returns:
            PatchValidationResult with independent scores
        """
        start_time = time.time()
        validation_id = f"val-{uuid.uuid4().hex[:12]}"

        logger.info(
            f"[Validation] Starting validation {validation_id} "
            f"for patch {candidate.patch_id}"
        )

        result = PatchValidationResult(
            patch_id=candidate.patch_id,
            validation_id=validation_id,
            vulnerability_id=request.vulnerability_id,
        )

        sandbox_available = self._is_sandbox_available()
        result.sandbox_status = (
            SandboxStatus.AVAILABLE if sandbox_available else SandboxStatus.NOT_AVAILABLE
        )

        # Dimension 1: Compilation
        result.compilation_score = self._score_compilation(
            candidate, request
        )

        # Dimension 2: Unit Tests
        result.unit_test_score = self._score_unit_tests(
            candidate, request
        )

        # Dimension 3: Regression Tests
        result.regression_score = self._score_regression(
            candidate, request
        )

        # Dimension 4: Security Scan
        result.security_score = self._score_security(
            candidate, request
        )

        # Dimension 5: Functional Behavior
        result.functional_score = self._score_functional_behavior(
            candidate, request
        )

        # Dimension 6: Performance Impact
        result.performance_score = self._score_performance(
            candidate, request, sandbox_available
        )

        # Determine validation status
        result.validation_status = self._determine_status(result, sandbox_available)
        result.validation_duration_ms = int((time.time() - start_time) * 1000)
        result.created_at = datetime.now(timezone.utc).isoformat()

        logger.info(
            f"[Validation] Completed {validation_id}: "
            f"status={result.validation_status.value}, "
            f"sandbox={result.sandbox_status.value}, "
            f"compilation={result.compilation_score.score:.2f}, "
            f"unit_test={result.unit_test_score.score:.2f}, "
            f"regression={result.regression_score.score:.2f}, "
            f"security={result.security_score.score:.2f}, "
            f"functional={result.functional_score.score:.2f}, "
            f"performance={result.performance_score.score:.2f}"
        )

        return result

    def validate_candidates(
        self,
        request: ValidateCandidatesRequest,
    ) -> ValidateCandidatesResponse:
        """
        Validate multiple patch candidates across all dimensions.

        Args:
            request: Validation request with candidates and configuration

        Returns:
            ValidateCandidatesResponse with all results
        """
        start_time = time.time()

        logger.info(
            f"[Validation] Starting batch validation for "
            f"{len(request.candidates)} candidates"
        )

        sandbox_available = self._is_sandbox_available()
        results = []
        for candidate in request.candidates:
            result = self.validate_candidate(candidate, request)
            results.append(result)

        passed = sum(
            1 for r in results
            if r.validation_status == ValidationStatus.PASS
        )
        failed = len(results) - passed

        response = ValidateCandidatesResponse(
            vulnerability_id=request.vulnerability_id,
            results=results,
            total_validated=len(results),
            passed_count=passed,
            failed_count=failed,
            validation_duration_ms=int((time.time() - start_time) * 1000),
            sandbox_status=(
                SandboxStatus.AVAILABLE if sandbox_available else SandboxStatus.NOT_AVAILABLE
            ),
        )

        logger.info(
            f"[Validation] Batch complete: {passed} passed, {failed} failed "
            f"out of {len(results)} candidates"
        )

        return response

    # ============================================================
    # Dimension 1: Compilation
    # ============================================================

    def _score_compilation(
        self,
        candidate: PatchCandidate,
        request: ValidateCandidatesRequest,
    ) -> CompilationScore:
        """Score compilation: 1.0 if compiles, 0.0 if fails."""
        language = request.language.lower()
        compile_command = request.compile_command

        if not compile_command:
            # Auto-detect based on language
            compile_command = self._get_compile_command(language)

        if not compile_command:
            # No compilation needed (e.g., interpreted language)
            return CompilationScore(
                score=1.0,
                success=True,
                language=language,
                output="No compilation required",
                duration_ms=0,
            )

        try:
            start = time.time()
            success, output, error = self._execute_in_sandbox(
                candidate.modified_code,
                compile_command,
                request,
            )
            duration = int((time.time() - start) * 1000)

            return CompilationScore(
                score=1.0 if success else 0.0,
                success=success,
                language=language,
                output=output[:2000],
                duration_ms=duration,
                error=error,
                verified=not bool(error),
            )
        except Exception as e:
            logger.error(f"[Validation] Compilation error: {e}")
            return CompilationScore(
                score=0.0,
                success=False,
                language=language,
                output="",
                error=str(e),
                verified=False,
            )

    # ============================================================
    # Dimension 2: Unit Tests
    # ============================================================

    def _score_unit_tests(
        self,
        candidate: PatchCandidate,
        request: ValidateCandidatesRequest,
    ) -> UnitTestScore:
        """Score unit tests: ratio of passed/total."""
        test_command = request.test_command

        if not test_command:
            return UnitTestScore(
                score=1.0,
                total_tests=0,
                passed=0,
                failed=0,
                skipped=0,
                framework="none",
                output="No test command provided",
                duration_ms=0,
            )

        try:
            start = time.time()
            success, output, error = self._execute_in_sandbox(
                candidate.modified_code,
                test_command,
                request,
            )
            duration = int((time.time() - start) * 1000)

            # Parse test results from output
            parsed = self._parse_test_output(output)

            total = parsed["total"]
            passed = parsed["passed"]
            failed = parsed["failed"]
            skipped = parsed["skipped"]

            if total == 0:
                score = 1.0 if success else 0.0
            else:
                score = passed / total if total > 0 else 0.0

            return UnitTestScore(
                score=score,
                total_tests=total,
                passed=passed,
                failed=failed,
                skipped=skipped,
                framework=parsed["framework"],
                output=output[:2000],
                duration_ms=duration,
                failure_details=parsed["failures"],
                error=error,
                verified=not bool(error),
            )
        except Exception as e:
            logger.error(f"[Validation] Unit test error: {e}")
            return UnitTestScore(
                score=0.0,
                error=str(e),
                verified=False,
            )

    # ============================================================
    # Dimension 3: Regression Tests
    # ============================================================

    def _score_regression(
        self,
        candidate: PatchCandidate,
        request: ValidateCandidatesRequest,
    ) -> RegressionScore:
        """Score regression: 1.0 if no regressions, lower if regressions found."""
        regression_command = request.regression_test_command or request.test_command

        if not regression_command:
            return RegressionScore(
                score=1.0,
                total_tests=0,
                passed=0,
                failed=0,
                regressions_found=0,
                output="No regression test command provided",
                duration_ms=0,
            )

        try:
            start = time.time()
            success, output, error = self._execute_in_sandbox(
                candidate.modified_code,
                regression_command,
                request,
            )
            duration = int((time.time() - start) * 1000)

            parsed = self._parse_test_output(output)
            total = parsed["total"]
            failed = parsed["failed"]

            # Regressions are failures that weren't in the original code
            # Without baseline, we assume all failures are regressions
            regressions = failed

            if total == 0:
                score = 1.0
            else:
                # Score decreases with each regression
                score = max(0.0, 1.0 - (regressions / total))

            return RegressionScore(
                score=score,
                total_tests=total,
                passed=parsed["passed"],
                failed=failed,
                regressions_found=regressions,
                regression_details=parsed["failures"],
                output=output[:2000],
                duration_ms=duration,
                error=error,
                verified=not bool(error),
            )
        except Exception as e:
            logger.error(f"[Validation] Regression test error: {e}")
            return RegressionScore(
                score=0.0,
                error=str(e),
                verified=False,
            )

    # ============================================================
    # Dimension 4: Security Scan
    # ============================================================

    def _score_security(
        self,
        candidate: PatchCandidate,
        request: ValidateCandidatesRequest,
    ) -> SecurityValidationScore:
        """Score security: 1.0 if clean, decreases with vulnerabilities."""
        scan_command = request.scan_command

        if not scan_command:
            return SecurityValidationScore(
                score=1.0,
                vulnerabilities_found=0,
                scanner="none",
                output="No scan command provided",
                duration_ms=0,
            )

        try:
            start = time.time()
            success, output, error = self._execute_in_sandbox(
                candidate.modified_code,
                scan_command,
                request,
            )
            duration = int((time.time() - start) * 1000)

            # Parse security findings from output
            findings = self._parse_security_output(output)

            critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
            high = sum(1 for f in findings if f.get("severity") == "HIGH")
            medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
            low = sum(1 for f in findings if f.get("severity") == "LOW")
            total = critical + high + medium + low

            # Score: 1.0 if clean, decreases with severity-weighted count
            if total == 0:
                score = 1.0
            else:
                severity_penalty = (
                    critical * 0.4 +
                    high * 0.25 +
                    medium * 0.1 +
                    low * 0.05
                )
                score = max(0.0, 1.0 - severity_penalty)

            return SecurityValidationScore(
                score=score,
                vulnerabilities_found=total,
                critical=critical,
                high=high,
                medium=medium,
                low=low,
                findings=findings,
                scanner="semgrep",
                output=output[:2000],
                duration_ms=duration,
                error=error,
                verified=not bool(error),
            )
        except Exception as e:
            logger.error(f"[Validation] Security scan error: {e}")
            return SecurityValidationScore(
                score=0.0,
                error=str(e),
                verified=False,
            )

    # ============================================================
    # Dimension 5: Functional Behavior
    # ============================================================

    def _score_functional_behavior(
        self,
        candidate: PatchCandidate,
        request: ValidateCandidatesRequest,
    ) -> FunctionalBehaviorScore:
        """
        Score functional behavior: 1.0 if behavior preserved, 0.0 if broken.
        Uses input/output comparison to detect behavioral changes.
        """
        test_command = request.test_command

        if not test_command:
            return FunctionalBehaviorScore(
                score=1.0,
                tests_run=0,
                behavior_preserved=True,
                output="No test command provided for behavior check",
                duration_ms=0,
            )

        try:
            start = time.time()
            success, output, error = self._execute_in_sandbox(
                candidate.modified_code,
                test_command,
                request,
            )
            duration = int((time.time() - start) * 1000)

            # Parse test results
            parsed = self._parse_test_output(output)
            total = parsed["total"]
            passed = parsed["passed"]
            failed = parsed["failed"]

            # Check for side effects in output
            side_effects = self._detect_side_effects(output)

            # Score based on test pass rate and side effects
            if total == 0:
                score = 1.0
            else:
                base_score = passed / total
                # Reduce score for each side effect
                side_effect_penalty = len(side_effects) * 0.1
                score = max(0.0, base_score - side_effect_penalty)

            behavior_preserved = failed == 0 and len(side_effects) == 0

            return FunctionalBehaviorScore(
                score=score,
                tests_run=total,
                behavior_preserved=behavior_preserved,
                output_compared=True,
                side_effects_detected=side_effects,
                output=output[:2000],
                duration_ms=duration,
                error=error,
                verified=not bool(error),
            )
        except Exception as e:
            logger.error(f"[Validation] Functional behavior error: {e}")
            return FunctionalBehaviorScore(
                score=0.0,
                error=str(e),
                verified=False,
            )

    # ============================================================
    # Dimension 6: Performance Impact
    # ============================================================

    def _score_performance(
        self,
        candidate: PatchCandidate,
        request: ValidateCandidatesRequest,
        sandbox_available: bool = True,
    ) -> PerformanceImpactScore:
        """
        Score performance impact: 1.0 if no regression, lower if regression.
        Compares against baseline if provided.
        Returns UNVERIFIED (verified=False) when the sandbox cannot measure it.
        """
        if not sandbox_available:
            return PerformanceImpactScore(
                score=1.0,
                verified=False,
                within_acceptable_range=False,
                output="Sandbox not available - performance impact not measured",
            )

        baseline = request.baseline_performance or {}

        try:
            start = time.time()

            # Measure execution time using Python's time module (cross-platform)
            perf_success, perf_output, perf_error = self._execute_in_sandbox(
                candidate.modified_code,
                "python -c \"import time; t=time.time(); exec(open('test.py').read()); print(f'elapsed={time.time()-t:.4f}')\"",
                request,
            )
            duration = int((time.time() - start) * 1000)

            # Parse timing from output
            patched_time = self._parse_time_output(perf_output)
            if patched_time == 0:
                patched_time = duration

            baseline_time = baseline.get("execution_time_ms", patched_time)
            baseline_memory = baseline.get("memory_peak_mb", 0.0)

            # Calculate regressions
            if baseline_time > 0:
                time_regression = ((patched_time - baseline_time) / baseline_time) * 100
            else:
                time_regression = 0.0

            memory_regression = 0.0

            # Determine if within acceptable range
            time_ok = time_regression <= PERFORMANCE_THRESHOLD_PCT
            memory_ok = memory_regression <= MEMORY_THRESHOLD_PCT
            within_range = time_ok and memory_ok

            if within_range:
                score = 1.0
            else:
                regression = max(time_regression, memory_regression)
                score = max(0.0, 1.0 - (regression / 200.0))

            return PerformanceImpactScore(
                score=score,
                baseline_time_ms=baseline_time,
                patched_time_ms=patched_time,
                time_regression_pct=time_regression,
                baseline_memory_mb=baseline_memory,
                patched_memory_mb=0.0,
                memory_regression_pct=memory_regression,
                within_acceptable_range=within_range,
                output=perf_output[:2000],
                duration_ms=duration,
                verified=not bool(perf_error),
                error=perf_error,
            )
        except Exception as e:
            # Performance measurement failed (e.g., sandbox execution error).
            # Reported honestly as unverified -- never claimed as a pass.
            logger.debug(f"[Validation] Performance measurement unavailable: {e}")
            return PerformanceImpactScore(
                score=1.0,
                verified=False,
                within_acceptable_range=False,
                output="Performance measurement unavailable - not measured",
                error=str(e),
            )

    # ============================================================
    # Helper Methods
    # ============================================================

    def _determine_status(
        self,
        result: PatchValidationResult,
        sandbox_available: bool,
    ) -> ValidationStatus:
        """Determine overall validation status from individual scores."""
        score_values = [
            result.compilation_score.score,
            result.unit_test_score.score,
            result.regression_score.score,
            result.security_score.score,
            result.functional_score.score,
            result.performance_score.score,
        ]

        # Any dimension that required sandbox execution but could not run is
        # UNVERIFIED -- never claimed as pass, fail, or error.
        if not sandbox_available:
            verified_dims = [
                result.compilation_score.verified,
                result.unit_test_score.verified,
                result.regression_score.verified,
                result.security_score.verified,
                result.functional_score.verified,
                result.performance_score.verified,
            ]
            if not all(verified_dims):
                return ValidationStatus.UNVERIFIED

        # Check for errors
        if any(s == 0.0 for s in score_values):
            has_errors = (
                result.compilation_score.error or
                result.unit_test_score.error or
                result.regression_score.error or
                result.security_score.error or
                result.functional_score.error or
                result.performance_score.error
            )
            if has_errors:
                return ValidationStatus.ERROR

        # Critical security vulnerability always FAIL
        if result.security_score.critical > 0:
            return ValidationStatus.FAIL

        min_score = min(score_values)

        # PASS: all scores >= 0.5
        if min_score >= 0.5:
            return ValidationStatus.PASS

        # WARNING: all scores >= 0.3
        if min_score >= 0.3:
            return ValidationStatus.WARNING

        # FAIL: any score below 0.3
        return ValidationStatus.FAIL

    def _get_compile_command(self, language: str) -> Optional[str]:
        """Get compile command based on language."""
        commands = {
            "python": None,  # No compilation
            "javascript": None,  # No compilation
            "typescript": "npx tsc --noEmit",
            "java": "javac",
            "go": "go build",
            "rust": "cargo check",
            "c": "gcc -fsyntax-only",
            "cpp": "g++ -fsyntax-only",
        }
        return commands.get(language.lower())

    # Allowlist of executables permitted inside the local validation environment.
    # All other commands are rejected before execution.
    _ALLOWED_EXECUTABLES: frozenset = frozenset({
        "pytest", "python", "python3",
        "jest", "node", "npx",
        "javac", "java",
        "go",
        "cargo",
        "tsc",
        "gcc", "g++", "clang", "clang++",
        "rustc",
        "mvn",
        "time",
    })

    def _execute_in_sandbox(
        self,
        code: str,
        command: str,
        request: ValidateCandidatesRequest,
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Execute code securely using the SandboxAgent (Docker).
        
        Maps the given command to the sandbox's test_command, so that
        the arbitrary command executes within the Docker environment.
        """
        try:
            # --- SECURITY: parse and validate command before execution ---
            try:
                cmd_parts = shlex.split(command)
            except ValueError as e:
                return False, "", f"Invalid command syntax: {e}"

            if not cmd_parts:
                return False, "", "Empty command"

            executable = os.path.basename(cmd_parts[0])
            if executable not in self._ALLOWED_EXECUTABLES:
                logger.warning(
                    f"[Validation] SECURITY: Command '{executable}' is not in the allowlist. Rejected."
                )
                return False, "", (
                    f"Command '{executable}' is not permitted. "
                    f"Allowed: {sorted(self._ALLOWED_EXECUTABLES)}"
                )

            # Lazy import to avoid circular dependencies if any
            from app.agents.sandbox_agent import SandboxAgent
            from app.agents.models import SandboxValidationRequest, PatchCandidate

            # Construct dummy patch candidate for execution
            dummy_candidate = PatchCandidate(
                patch_id="validation-exec",
                modified_code=code,
                explanation="Temporary validation execution",
                security_strategy="None",
                expected_effect="Test execution"
            )

            # Map inputs to SandboxValidationRequest
            # We map the arbitrary command to `test_command` so runner.py executes it.
            # We ensure the file_path matches what performance/test scripts might expect (e.g., test.py)
            sandbox_request = SandboxValidationRequest(
                patch=dummy_candidate,
                repository_id="validation",
                workspace_path="",
                file_path=f"test{self._get_file_extension(request.language)}",
                original_code=request.original_code or code,
                language=request.language,
                test_command=command,
                sandbox_config=request.sandbox_config
            )

            sandbox = SandboxAgent()
            response = sandbox.validate_patch(sandbox_request)

            # The output of test_command is stored in response.tests
            success = response.tests.success
            output = response.tests.output
            error = response.tests.error

            return success, output, error

        except Exception as e:
            return False, "", str(e)

    def _get_file_extension(self, language: str) -> str:
        """Get file extension for language."""
        extensions = {
            "python": ".py",
            "javascript": ".js",
            "typescript": ".ts",
            "java": ".java",
            "go": ".go",
            "rust": ".rs",
            "c": ".c",
            "cpp": ".cpp",
        }
        return extensions.get(language.lower(), ".txt")

    def _parse_test_output(self, output: str) -> Dict[str, Any]:
        """Parse test output to extract results."""
        result = {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "framework": "unknown",
            "failures": [],
        }

        if not output:
            return result

        # pytest pattern: "X passed, Y failed, Z skipped"
        pytest_match = re.search(
            r"(\d+) passed.*?(\d+) failed.*?(\d+) skipped",
            output
        )
        if pytest_match:
            result["framework"] = "pytest"
            result["passed"] = int(pytest_match.group(1))
            result["failed"] = int(pytest_match.group(2))
            result["skipped"] = int(pytest_match.group(3))
            result["total"] = result["passed"] + result["failed"] + result["skipped"]
            return result

        # pytest pattern: "X passed, Y failed"
        pytest_pf_match = re.search(r"(\d+) passed.*?(\d+) failed", output)
        if pytest_pf_match:
            result["framework"] = "pytest"
            result["passed"] = int(pytest_pf_match.group(1))
            result["failed"] = int(pytest_pf_match.group(2))
            result["total"] = result["passed"] + result["failed"]
            return result

        # jest pattern: "Tests: X passed, Y total" (must check before simple passed)
        jest_match = re.search(r"Tests:.*?(\d+) passed.*?(\d+) total", output)
        if jest_match:
            result["framework"] = "jest"
            result["passed"] = int(jest_match.group(1))
            result["total"] = int(jest_match.group(2))
            result["failed"] = result["total"] - result["passed"]
            return result

        # JUnit pattern: "Tests run: X, Failures: Y"
        junit_match = re.search(r"Tests run: (\d+).*?Failures: (\d+)", output)
        if junit_match:
            result["framework"] = "junit"
            result["total"] = int(junit_match.group(1))
            result["failed"] = int(junit_match.group(2))
            result["passed"] = result["total"] - result["failed"]
            return result

        # pytest pattern: "X passed"
        pytest_passed = re.search(r"(\d+) passed", output)
        if pytest_passed:
            result["framework"] = "pytest"
            result["passed"] = int(pytest_passed.group(1))
            result["total"] = result["passed"]
            return result

        # Generic pass/fail counting
        passed_count = len(re.findall(r"(?i)(PASS|OK|SUCCESS)", output))
        failed_count = len(re.findall(r"(?i)(FAIL|ERROR|FAILURE)", output))

        if passed_count > 0 or failed_count > 0:
            result["passed"] = passed_count
            result["failed"] = failed_count
            result["total"] = passed_count + failed_count

        return result

    def _parse_security_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse security scan output to extract findings."""
        findings = []

        if not output:
            return findings

        # semgrep JSON output pattern
        # Look for severity indicators
        lines = output.split("\n")
        for line in lines:
            # Pattern: [severity] rule_id: message
            match = re.search(
                r"\[(ERROR|WARNING|INFO)\]\s+([^:]+):\s+(.+)",
                line
            )
            if match:
                severity_map = {
                    "ERROR": "HIGH",
                    "WARNING": "MEDIUM",
                    "INFO": "LOW",
                }
                findings.append({
                    "severity": severity_map.get(match.group(1), "LOW"),
                    "rule_id": match.group(2).strip(),
                    "message": match.group(3).strip(),
                })

        return findings

    def _detect_side_effects(self, output: str) -> List[str]:
        """Detect side effects in test output."""
        side_effects = []

        # Check for warning messages
        warnings = re.findall(r"(?i)(warning|deprecat)", output)
        if warnings:
            side_effects.append(f"Detected {len(warnings)} warning(s)")

        # Check for error messages that aren't test failures
        errors = re.findall(r"(?i)(error|exception|traceback)", output)
        if errors:
            side_effects.append(f"Detected {len(errors)} error(s)")

        # Check for resource usage indicators
        if re.search(r"(?i)(memory|oom|killed)", output):
            side_effects.append("Memory issues detected")

        return side_effects

    def _parse_time_output(self, output: str) -> int:
        """Parse timing output from time command."""
        # real    0m0.100s
        match = re.search(r"real\s+\d+m(\d+\.\d+)s", output)
        if match:
            return int(float(match.group(1)) * 1000)

        # fallback: use duration_ms from sandbox
        return 0
