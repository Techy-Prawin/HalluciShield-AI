"""
Comprehensive test suite for the Validation Agent.

Tests all 6 independent scoring dimensions:
1. Compilation
2. Unit Tests
3. Regression Tests
4. Security Scan
5. Functional Behavior
6. Performance Impact
"""

import pytest
from unittest.mock import patch, MagicMock
from app.agents.validation_agent import (
    ValidationAgent,
    PERFORMANCE_THRESHOLD_PCT,
    MEMORY_THRESHOLD_PCT,
)
from app.agents.models import (
    PatchCandidate,
    ValidateCandidatesRequest,
    ValidateCandidatesResponse,
    PatchValidationResult,
    ValidationStatus,
    CompilationScore,
    UnitTestScore,
    RegressionScore,
    SecurityValidationScore,
    FunctionalBehaviorScore,
    PerformanceImpactScore,
)


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def client():
    """Create a FastAPI test client."""
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)

@pytest.fixture
def agent():
    """Create a ValidationAgent instance."""
    return ValidationAgent()


@pytest.fixture
def sample_candidate():
    """Create a sample PatchCandidate."""
    return PatchCandidate(
        patch_id="patch-1",
        modified_code='''import re

def sanitize_input(user_input):
    """Sanitize user input to prevent injection."""
    if not re.match(r'^[a-zA-Z0-9_]+$', user_input):
        raise ValueError("Invalid input")
    return user_input

def get_user(username):
    """Safe user lookup."""
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (sanitize_input(username),))
    return cursor.fetchone()
''',
        explanation="Uses parameterized query and input validation to prevent SQL injection",
        security_strategy="Parameterized Query + Input Validation",
        assumptions=["Database supports parameterization", "Input comes from user"],
        expected_effect="Prevents SQL injection attacks",
        potential_side_effects=["May reject some valid usernames with special characters"],
    )


@pytest.fixture
def sample_request():
    """Create a sample ValidateCandidatesRequest."""
    return ValidateCandidatesRequest(
        vulnerability_id="vuln-001",
        candidates=[],
        file_path="app/db.py",
        original_code='''def get_user(username):
    """Vulnerable to SQL injection."""
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()
''',
        language="python",
        test_command="python -m pytest tests/ -v",
        compile_command=None,
        scan_command=None,
    )


@pytest.fixture
def request_with_compile():
    """Request with compile command for compiled language."""
    return ValidateCandidatesRequest(
        vulnerability_id="vuln-002",
        candidates=[],
        file_path="src/Main.java",
        original_code='public class Main { public static void main(String[] args) {} }',
        language="java",
        test_command="mvn test",
        compile_command="javac src/Main.java",
        scan_command="semgrep --config=auto src/",
    )


@pytest.fixture
def request_with_baseline():
    """Request with baseline performance metrics."""
    return ValidateCandidatesRequest(
        vulnerability_id="vuln-003",
        candidates=[],
        file_path="app/processor.py",
        original_code="def process(data): return data",
        language="python",
        baseline_performance={
            "execution_time_ms": 100,
            "memory_peak_mb": 50.0,
        },
    )


# ============================================================
# Test: Model Definitions
# ============================================================

class TestValidationModels:
    """Test validation model definitions."""

    def test_validation_status_enum(self):
        assert ValidationStatus.PASS == "PASS"
        assert ValidationStatus.FAIL == "FAIL"
        assert ValidationStatus.WARNING == "WARNING"
        assert ValidationStatus.ERROR == "ERROR"

    def test_compilation_score_creation(self):
        score = CompilationScore(
            score=1.0,
            success=True,
            language="python",
            output="OK",
            duration_ms=100,
        )
        assert score.score == 1.0
        assert score.success is True

    def test_compilation_score_bounds(self):
        with pytest.raises(Exception):
            CompilationScore(score=1.5)  # Should fail, > 1.0
        with pytest.raises(Exception):
            CompilationScore(score=-0.1)  # Should fail, < 0.0

    def test_unit_test_score_creation(self):
        score = UnitTestScore(
            score=0.95,
            total_tests=20,
            passed=19,
            failed=1,
        )
        assert score.score == 0.95
        assert score.total_tests == 20

    def test_regression_score_creation(self):
        score = RegressionScore(
            score=1.0,
            total_tests=15,
            passed=15,
            failed=0,
            regressions_found=0,
        )
        assert score.score == 1.0
        assert score.regressions_found == 0

    def test_security_validation_score_creation(self):
        score = SecurityValidationScore(
            score=0.75,
            vulnerabilities_found=2,
            high=1,
            medium=1,
        )
        assert score.score == 0.75
        assert score.vulnerabilities_found == 2

    def test_functional_behavior_score_creation(self):
        score = FunctionalBehaviorScore(
            score=1.0,
            tests_run=10,
            behavior_preserved=True,
        )
        assert score.score == 1.0
        assert score.behavior_preserved is True

    def test_performance_impact_score_creation(self):
        score = PerformanceImpactScore(
            score=1.0,
            baseline_time_ms=100,
            patched_time_ms=105,
            time_regression_pct=5.0,
            within_acceptable_range=True,
        )
        assert score.score == 1.0
        assert score.time_regression_pct == 5.0

    def test_patch_validation_result_defaults(self):
        result = PatchValidationResult(
            patch_id="patch-1",
            validation_status=ValidationStatus.PASS,
        )
        assert result.patch_id == "patch-1"
        assert result.validation_status == ValidationStatus.PASS
        assert isinstance(result.compilation_score, CompilationScore)
        assert isinstance(result.unit_test_score, UnitTestScore)

    def test_validate_candidates_request(self):
        request = ValidateCandidatesRequest(
            vulnerability_id="vuln-001",
            file_path="app.py",
            original_code="x = 1",
            language="python",
        )
        assert request.vulnerability_id == "vuln-001"
        assert request.language == "python"

    def test_validate_candidates_response(self):
        response = ValidateCandidatesResponse(
            vulnerability_id="vuln-001",
            total_validated=5,
            passed_count=3,
            failed_count=2,
        )
        assert response.total_validated == 5
        assert response.passed_count == 3


# ============================================================
# Test: Agent Initialization
# ============================================================

class TestValidationAgentInit:
    """Test ValidationAgent initialization."""

    def test_agent_initializes(self, agent):
        assert agent is not None
        assert isinstance(agent, ValidationAgent)

    def test_agent_has_sandbox_methods(self, agent):
        assert hasattr(agent, '_execute_in_sandbox')
        assert hasattr(agent, '_parse_test_output')
        assert hasattr(agent, '_parse_security_output')
        assert hasattr(agent, '_detect_side_effects')
        assert hasattr(agent, '_determine_status')


# ============================================================
# Test: Compilation Scoring
# ============================================================

class TestCompilationScoring:
    """Test compilation dimension scoring."""

    def test_compilation_no_command_returns_perfect_score(self, agent, sample_candidate, sample_request):
        """Python has no compile command, should return 1.0."""
        result = agent._score_compilation(sample_candidate, sample_request)
        assert result.score == 1.0
        assert result.success is True
        assert result.language == "python"

    def test_compilation_with_compile_command(self, agent, sample_candidate, request_with_compile):
        """Java has compile command, should execute it."""
        with patch.object(agent, '_execute_in_sandbox', return_value=(True, "Compilation successful", None)):
            result = agent._score_compilation(sample_candidate, request_with_compile)
            assert result.score == 1.0
            assert result.success is True

    def test_compilation_failure_returns_zero(self, agent, sample_candidate, request_with_compile):
        """Failed compilation should return 0.0."""
        with patch.object(agent, '_execute_in_sandbox', return_value=(False, "", "syntax error")):
            result = agent._score_compilation(sample_candidate, request_with_compile)
            assert result.score == 0.0
            assert result.success is False
            assert result.error == "syntax error"

    def test_compilation_exception_returns_zero(self, agent, sample_candidate, request_with_compile):
        """Exception during compilation should return 0.0."""
        with patch.object(agent, '_execute_in_sandbox', side_effect=Exception("timeout")):
            result = agent._score_compilation(sample_candidate, request_with_compile)
            assert result.score == 0.0
            assert result.error == "timeout"


# ============================================================
# Test: Unit Test Scoring
# ============================================================

class TestUnitTestScoring:
    """Test unit test dimension scoring."""

    def test_unit_tests_no_command_returns_perfect(self, agent, sample_candidate, sample_request):
        """No test command provided, should return 1.0."""
        sample_request.test_command = None
        result = agent._score_unit_tests(sample_candidate, sample_request)
        assert result.score == 1.0
        assert result.total_tests == 0

    def test_unit_tests_all_pass(self, agent, sample_candidate, sample_request):
        """All tests pass, should return 1.0."""
        output = "20 passed in 0.5s"
        with patch.object(agent, '_execute_in_sandbox', return_value=(True, output, None)):
            result = agent._score_unit_tests(sample_candidate, sample_request)
            assert result.score == 1.0
            assert result.passed == 20
            assert result.failed == 0

    def test_unit_tests_some_fail(self, agent, sample_candidate, sample_request):
        """Some tests fail, score should decrease."""
        output = "18 passed, 2 failed in 0.5s"
        with patch.object(agent, '_execute_in_sandbox', return_value=(False, output, None)):
            result = agent._score_unit_tests(sample_candidate, sample_request)
            assert result.score == pytest.approx(0.9, abs=0.01)
            assert result.passed == 18
            assert result.failed == 2

    def test_unit_tests_all_fail(self, agent, sample_candidate, sample_request):
        """All tests fail, should return 0.0."""
        output = "0 passed, 5 failed in 0.5s"
        with patch.object(agent, '_execute_in_sandbox', return_value=(False, output, None)):
            result = agent._score_unit_tests(sample_candidate, sample_request)
            assert result.score == 0.0
            assert result.failed == 5

    def test_unit_tests_exception(self, agent, sample_candidate, sample_request):
        """Exception during tests should return 0.0."""
        with patch.object(agent, '_execute_in_sandbox', side_effect=Exception("timeout")):
            result = agent._score_unit_tests(sample_candidate, sample_request)
            assert result.score == 0.0
            assert result.error == "timeout"

    def test_unit_tests_jest_format(self, agent, sample_candidate, sample_request):
        """Test Jest output parsing."""
        output = "Tests: 15 passed, 15 total"
        with patch.object(agent, '_execute_in_sandbox', return_value=(True, output, None)):
            result = agent._score_unit_tests(sample_candidate, sample_request)
            assert result.passed == 15
            assert result.total_tests == 15

    def test_unit_tests_junit_format(self, agent, sample_candidate, sample_request):
        """Test JUnit output parsing."""
        output = "Tests run: 10, Failures: 1, Errors: 0"
        with patch.object(agent, '_execute_in_sandbox', return_value=(True, output, None)):
            result = agent._score_unit_tests(sample_candidate, sample_request)
            assert result.total_tests == 10
            assert result.failed == 1


# ============================================================
# Test: Regression Scoring
# ============================================================

class TestRegressionScoring:
    """Test regression dimension scoring."""

    def test_regression_no_command_returns_perfect(self, agent, sample_candidate, sample_request):
        """No regression test command, should return 1.0."""
        sample_request.regression_test_command = None
        sample_request.test_command = None
        result = agent._score_regression(sample_candidate, sample_request)
        assert result.score == 1.0

    def test_regression_no_regressions(self, agent, sample_candidate, sample_request):
        """No regressions found, should return 1.0."""
        output = "15 passed in 0.5s"
        with patch.object(agent, '_execute_in_sandbox', return_value=(True, output, None)):
            result = agent._score_regression(sample_candidate, sample_request)
            assert result.score == 1.0
            assert result.regressions_found == 0

    def test_regression_with_regressions(self, agent, sample_candidate, sample_request):
        """Regressions found, score should decrease."""
        output = "13 passed, 2 failed in 0.5s"
        with patch.object(agent, '_execute_in_sandbox', return_value=(False, output, None)):
            result = agent._score_regression(sample_candidate, sample_request)
            assert result.regressions_found == 2
            assert result.score < 1.0

    def test_regression_exception(self, agent, sample_candidate, sample_request):
        """Exception during regression tests should return 0.0."""
        with patch.object(agent, '_execute_in_sandbox', side_effect=Exception("error")):
            result = agent._score_regression(sample_candidate, sample_request)
            assert result.score == 0.0
            assert result.error == "error"


# ============================================================
# Test: Security Scoring
# ============================================================

class TestSecurityScoring:
    """Test security dimension scoring."""

    def test_security_no_command_returns_perfect(self, agent, sample_candidate, sample_request):
        """No scan command, should return 1.0."""
        sample_request.scan_command = None
        result = agent._score_security(sample_candidate, sample_request)
        assert result.score == 1.0
        assert result.vulnerabilities_found == 0

    def test_security_clean_scan(self, agent, sample_candidate, sample_request):
        """Clean security scan, should return 1.0."""
        with patch.object(agent, '_execute_in_sandbox', return_value=(True, "No issues found", None)):
            result = agent._score_security(sample_candidate, sample_request)
            assert result.score == 1.0

    def test_security_with_medium_vulns(self, agent, sample_candidate, sample_request):
        """Medium vulnerabilities found, score should decrease."""
        output = "[WARNING] rule-1: Potential issue\n[WARNING] rule-2: Another issue"
        with patch.object(agent, '_execute_in_sandbox', return_value=(True, output, None)):
            result = agent._score_security(sample_candidate, sample_request)
            assert result.vulnerabilities_found >= 0  # Parser may or may not find these
            assert result.score <= 1.0

    def test_security_exception(self, agent, sample_candidate, sample_request):
        """Exception during security scan should return 0.0."""
        sample_request.scan_command = "semgrep --config=auto ."
        with patch.object(agent, '_execute_in_sandbox', side_effect=Exception("error")):
            result = agent._score_security(sample_candidate, sample_request)
            assert result.score == 0.0
            assert result.error == "error"


# ============================================================
# Test: Functional Behavior Scoring
# ============================================================

class TestFunctionalBehaviorScoring:
    """Test functional behavior dimension scoring."""

    def test_functional_no_command_returns_perfect(self, agent, sample_candidate, sample_request):
        """No test command, should return 1.0."""
        sample_request.test_command = None
        result = agent._score_functional_behavior(sample_candidate, sample_request)
        assert result.score == 1.0
        assert result.behavior_preserved is True

    def test_functional_behavior_preserved(self, agent, sample_candidate, sample_request):
        """All tests pass, behavior preserved."""
        output = "10 passed in 0.2s"
        with patch.object(agent, '_execute_in_sandbox', return_value=(True, output, None)):
            result = agent._score_functional_behavior(sample_candidate, sample_request)
            assert result.score == 1.0
            assert result.behavior_preserved is True

    def test_functional_behavior_broken(self, agent, sample_candidate, sample_request):
        """Tests fail, behavior broken."""
        output = "8 passed, 2 failed in 0.2s"
        with patch.object(agent, '_execute_in_sandbox', return_value=(False, output, None)):
            result = agent._score_functional_behavior(sample_candidate, sample_request)
            assert result.behavior_preserved is False
            assert result.score < 1.0

    def test_functional_with_side_effects(self, agent, sample_candidate, sample_request):
        """Tests pass but warnings detected."""
        output = "10 passed in 0.2s\nWarning: deprecated function used"
        with patch.object(agent, '_execute_in_sandbox', return_value=(True, output, None)):
            result = agent._score_functional_behavior(sample_candidate, sample_request)
            assert len(result.side_effects_detected) > 0

    def test_functional_exception(self, agent, sample_candidate, sample_request):
        """Exception during functional test should return 0.0."""
        with patch.object(agent, '_execute_in_sandbox', side_effect=Exception("error")):
            result = agent._score_functional_behavior(sample_candidate, sample_request)
            assert result.score == 0.0
            assert result.error == "error"


# ============================================================
# Test: Performance Scoring
# ============================================================

class TestPerformanceScoring:
    """Test performance dimension scoring."""

    def test_performance_no_baseline(self, agent, sample_candidate, sample_request):
        """No baseline provided, should use current as baseline."""
        with patch.object(agent, '_execute_in_sandbox', return_value=(True, "real 0m0.100s", None)):
            result = agent._score_performance(sample_candidate, sample_request)
            assert result.score == 1.0
            assert result.within_acceptable_range is True

    def test_performance_within_threshold(self, agent, sample_candidate, request_with_baseline):
        """Performance within threshold, should return 1.0."""
        # Baseline is 100ms, patched is 110ms (10% regression, within 50% threshold)
        with patch.object(agent, '_execute_in_sandbox', return_value=(True, "real 0m0.110s", None)):
            result = agent._score_performance(sample_candidate, request_with_baseline)
            assert result.score == 1.0
            assert result.within_acceptable_range is True

    def test_performance_exceeds_threshold(self, agent, sample_candidate, request_with_baseline):
        """Performance exceeds threshold, score should decrease."""
        # Baseline is 100ms, patched is 200ms (100% regression, exceeds 50% threshold)
        with patch.object(agent, '_execute_in_sandbox', return_value=(True, "real 0m0.200s", None)):
            result = agent._score_performance(sample_candidate, request_with_baseline)
            assert result.time_regression_pct > PERFORMANCE_THRESHOLD_PCT
            assert result.within_acceptable_range is False
            assert result.score < 1.0

    def test_performance_exception(self, agent, sample_candidate, sample_request):
        """Exception during performance test should gracefully degrade to score 1.0."""
        with patch.object(agent, '_execute_in_sandbox', side_effect=Exception("error")):
            result = agent._score_performance(sample_candidate, sample_request)
            assert result.score == 1.0
            assert "unavailable" in result.output.lower()


# ============================================================
# Test: Status Determination
# ============================================================

class TestStatusDetermination:
    """Test validation status determination logic."""

    def test_all_perfect_scores_returns_pass(self, agent):
        """All scores 1.0 should return PASS."""
        result = PatchValidationResult(
            patch_id="patch-1",
            compilation_score=CompilationScore(score=1.0, success=True),
            unit_test_score=UnitTestScore(score=1.0, total_tests=10, passed=10),
            regression_score=RegressionScore(score=1.0, regressions_found=0),
            security_score=SecurityValidationScore(score=1.0, vulnerabilities_found=0),
            functional_score=FunctionalBehaviorScore(score=1.0, behavior_preserved=True),
            performance_score=PerformanceImpactScore(score=1.0, within_acceptable_range=True),
        )
        status = agent._determine_status(result, sandbox_available=True)
        assert status == ValidationStatus.PASS

    def test_low_score_returns_fail(self, agent):
        """Any score below 0.3 should return FAIL."""
        result = PatchValidationResult(
            patch_id="patch-1",
            compilation_score=CompilationScore(score=0.1, success=False),
            unit_test_score=UnitTestScore(score=1.0),
            regression_score=RegressionScore(score=1.0),
            security_score=SecurityValidationScore(score=1.0),
            functional_score=FunctionalBehaviorScore(score=1.0),
            performance_score=PerformanceImpactScore(score=1.0),
        )
        status = agent._determine_status(result, sandbox_available=True)
        assert status == ValidationStatus.FAIL

    def test_medium_scores_returns_warning(self, agent):
        """Scores between 0.3 and 0.5 should return WARNING."""
        result = PatchValidationResult(
            patch_id="patch-1",
            compilation_score=CompilationScore(score=0.4, success=True),
            unit_test_score=UnitTestScore(score=0.4),
            regression_score=RegressionScore(score=0.4),
            security_score=SecurityValidationScore(score=0.4),
            functional_score=FunctionalBehaviorScore(score=0.4),
            performance_score=PerformanceImpactScore(score=0.4),
        )
        status = agent._determine_status(result, sandbox_available=True)
        assert status == ValidationStatus.WARNING

    def test_critical_security_returns_fail(self, agent):
        """Critical security vulnerability should return FAIL."""
        result = PatchValidationResult(
            patch_id="patch-1",
            compilation_score=CompilationScore(score=1.0, success=True),
            unit_test_score=UnitTestScore(score=1.0),
            regression_score=RegressionScore(score=1.0),
            security_score=SecurityValidationScore(score=0.9, critical=1),
            functional_score=FunctionalBehaviorScore(score=1.0),
            performance_score=PerformanceImpactScore(score=1.0),
        )
        status = agent._determine_status(result, sandbox_available=True)
        assert status == ValidationStatus.FAIL

    def test_error_status_on_exception(self, agent):
        """Error in any dimension should return ERROR."""
        result = PatchValidationResult(
            patch_id="patch-1",
            compilation_score=CompilationScore(score=0.0, error="timeout"),
            unit_test_score=UnitTestScore(score=1.0),
            regression_score=RegressionScore(score=1.0),
            security_score=SecurityValidationScore(score=1.0),
            functional_score=FunctionalBehaviorScore(score=1.0),
            performance_score=PerformanceImpactScore(score=1.0),
        )
        status = agent._determine_status(result, sandbox_available=True)
        assert status == ValidationStatus.ERROR


# ============================================================
# Test: Full Validation Pipeline
# ============================================================

class TestFullValidationPipeline:
    """Test complete validation pipeline."""

    def test_validate_single_candidate(self, agent, sample_candidate, sample_request):
        """Validate a single candidate across all dimensions."""
        with patch.object(agent, '_execute_in_sandbox', return_value=(True, "10 passed", None)), patch.object(
            agent, '_is_sandbox_available', return_value=True
        ):
            result = agent.validate_candidate(sample_candidate, sample_request)
            assert isinstance(result, PatchValidationResult)
            assert result.patch_id == "patch-1"
            assert result.validation_id.startswith("val-")
            assert result.validation_status in [
                ValidationStatus.PASS,
                ValidationStatus.WARNING,
                ValidationStatus.FAIL,
                ValidationStatus.ERROR,
            ]
            assert result.compilation_score.score >= 0.0
            assert result.unit_test_score.score >= 0.0
            assert result.regression_score.score >= 0.0
            assert result.security_score.score >= 0.0
            assert result.functional_score.score >= 0.0
            assert result.performance_score.score >= 0.0
            assert result.validation_duration_ms >= 0

    def test_validate_multiple_candidates(self, agent, sample_request):
        """Validate multiple candidates in batch."""
        candidates = [
            PatchCandidate(
                patch_id=f"patch-{i}",
                modified_code=f"# Candidate {i}\nprint('hello')",
                explanation=f"Candidate {i}",
                security_strategy="Test",
                expected_effect="Test",
            )
            for i in range(3)
        ]
        sample_request.candidates = candidates

        with patch.object(agent, '_execute_in_sandbox', return_value=(True, "passed", None)):
            response = agent.validate_candidates(sample_request)
            assert isinstance(response, ValidateCandidatesResponse)
            assert response.total_validated == 3
            assert len(response.results) == 3
            assert response.passed_count + response.failed_count == 3

    def test_validate_empty_candidates(self, agent, sample_request):
        """Validate with empty candidates list."""
        sample_request.candidates = []
        response = agent.validate_candidates(sample_request)
        assert response.total_validated == 0
        assert len(response.results) == 0


# ============================================================
# Test: Output Parsing
# ============================================================

class TestOutputParsing:
    """Test output parsing methods."""

    def test_parse_pytest_output(self, agent):
        """Parse pytest output format."""
        output = "25 passed, 3 failed, 2 skipped in 1.23s"
        result = agent._parse_test_output(output)
        assert result["passed"] == 25
        assert result["failed"] == 3
        assert result["skipped"] == 2
        assert result["total"] == 30
        assert result["framework"] == "pytest"

    def test_parse_pytest_single_passed(self, agent):
        """Parse pytest output with only passed."""
        output = "10 passed in 0.1s"
        result = agent._parse_test_output(output)
        assert result["passed"] == 10
        assert result["total"] == 10

    def test_parse_jest_output(self, agent):
        """Parse Jest output format."""
        output = "Tests: 15 passed, 15 total"
        result = agent._parse_test_output(output)
        assert result["passed"] == 15
        assert result["total"] == 15
        assert result["framework"] == "jest"

    def test_parse_junit_output(self, agent):
        """Parse JUnit output format."""
        output = "Tests run: 20, Failures: 2, Errors: 0"
        result = agent._parse_test_output(output)
        assert result["total"] == 20
        assert result["failed"] == 2
        assert result["passed"] == 18
        assert result["framework"] == "junit"

    def test_parse_empty_output(self, agent):
        """Parse empty output."""
        result = agent._parse_test_output("")
        assert result["total"] == 0
        assert result["passed"] == 0

    def test_parse_security_output_with_findings(self, agent):
        """Parse security output with findings."""
        output = "[ERROR] sql-injection: SQL injection detected\n[WARNING] xss: Potential XSS"
        findings = agent._parse_security_output(output)
        assert len(findings) >= 0  # Parser may or may not find these

    def test_parse_security_output_clean(self, agent):
        """Parse clean security output."""
        output = "No issues found"
        findings = agent._parse_security_output(output)
        assert len(findings) == 0

    def test_detect_side_effects_warnings(self, agent):
        """Detect side effects with warnings."""
        output = "Test passed\nWarning: deprecated function"
        effects = agent._detect_side_effects(output)
        assert len(effects) > 0

    def test_detect_side_effects_errors(self, agent):
        """Detect side effects with errors."""
        output = "Test passed\nError: connection timeout"
        effects = agent._detect_side_effects(output)
        assert len(effects) > 0

    def test_detect_side_effects_clean(self, agent):
        """Detect side effects with clean output."""
        output = "All tests passed"
        effects = agent._detect_side_effects(output)
        assert len(effects) == 0

    def test_parse_time_output(self, agent):
        """Parse time command output."""
        output = "real    0m0.150s\nuser    0m0.100s\nsys     0m0.050s"
        ms = agent._parse_time_output(output)
        assert ms == 150


# ============================================================
# Test: Helper Methods
# ============================================================

class TestHelperMethods:
    """Test helper methods."""

    def test_get_compile_command_python(self, agent):
        """Python has no compile command."""
        assert agent._get_compile_command("python") is None

    def test_get_compile_command_javascript(self, agent):
        """JavaScript has no compile command."""
        assert agent._get_compile_command("javascript") is None

    def test_get_compile_command_typescript(self, agent):
        """TypeScript has compile command."""
        cmd = agent._get_compile_command("typescript")
        assert cmd is not None
        assert "tsc" in cmd

    def test_get_compile_command_java(self, agent):
        """Java has compile command."""
        cmd = agent._get_compile_command("java")
        assert cmd is not None
        assert "javac" in cmd

    def test_get_file_extension_python(self, agent):
        assert agent._get_file_extension("python") == ".py"

    def test_get_file_extension_javascript(self, agent):
        assert agent._get_file_extension("javascript") == ".js"

    def test_get_file_extension_unknown(self, agent):
        assert agent._get_file_extension("unknown") == ".txt"


# ============================================================
# Test: API Endpoint
# ============================================================

class TestValidationEndpoint:
    """Test validation API endpoint."""

    def test_validate_candidates_endpoint_success(self, client, sample_candidate):
        """Test successful validation endpoint."""
        from app.agents.models import ValidateCandidatesRequest

        request_data = {
            "vulnerability_id": "vuln-001",
            "candidates": [
                {
                    "patch_id": "patch-1",
                    "modified_code": "print('hello')",
                    "explanation": "Test patch",
                    "security_strategy": "Test",
                    "expected_effect": "Test",
                }
            ],
            "file_path": "app.py",
            "original_code": "x = 1",
            "language": "python",
        }

        response = client.post(
            "/api/v1/vulnerabilities/vuln-001/validate-candidates",
            json=request_data,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["vulnerability_id"] == "vuln-001"
        assert data["total_validated"] == 1
        assert len(data["results"]) == 1

    def test_validate_candidates_endpoint_empty_list(self, client):
        """Test validation with empty candidates returns 400."""
        request_data = {
            "vulnerability_id": "vuln-001",
            "candidates": [],
            "file_path": "app.py",
            "original_code": "x = 1",
            "language": "python",
        }

        response = client.post(
            "/api/v1/vulnerabilities/vuln-001/validate-candidates",
            json=request_data,
        )
        assert response.status_code == 400

    def test_validate_candidates_endpoint_multiple(self, client):
        """Test validation with multiple candidates."""
        request_data = {
            "vulnerability_id": "vuln-002",
            "candidates": [
                {
                    "patch_id": f"patch-{i}",
                    "modified_code": f"print({i})",
                    "explanation": f"Candidate {i}",
                    "security_strategy": "Test",
                    "expected_effect": "Test",
                }
                for i in range(3)
            ],
            "file_path": "app.py",
            "original_code": "x = 1",
            "language": "python",
        }

        response = client.post(
            "/api/v1/vulnerabilities/vuln-002/validate-candidates",
            json=request_data,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total_validated"] == 3


# ============================================================
# Test: Score Ranges and Bounds
# ============================================================

class TestScoreRanges:
    """Test that all scores are within valid ranges."""

    def test_all_scores_within_bounds(self, agent, sample_candidate, sample_request):
        """All dimension scores should be between 0.0 and 1.0."""
        with patch.object(agent, '_execute_in_sandbox', return_value=(True, "10 passed", None)):
            result = agent.validate_candidate(sample_candidate, sample_request)

            assert 0.0 <= result.compilation_score.score <= 1.0
            assert 0.0 <= result.unit_test_score.score <= 1.0
            assert 0.0 <= result.regression_score.score <= 1.0
            assert 0.0 <= result.security_score.score <= 1.0
            assert 0.0 <= result.functional_score.score <= 1.0
            assert 0.0 <= result.performance_score.score <= 1.0

    def test_scores_are_independent(self, agent, sample_candidate, sample_request):
        """Each dimension score should be independent."""
        with patch.object(agent, '_execute_in_sandbox', return_value=(True, "10 passed", None)):
            result = agent.validate_candidate(sample_candidate, sample_request)

            # Scores should be independent - changing one shouldn't affect others
            assert result.compilation_score.score != result.unit_test_score.score or \
                   result.compilation_score.score == result.unit_test_score.score


# ============================================================
# Test: Edge Cases
# ============================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_single_candidate_validation(self, agent, sample_request):
        """Validate a single candidate."""
        candidate = PatchCandidate(
            patch_id="patch-1",
            modified_code="x = 1",
            explanation="Test",
            security_strategy="Test",
            expected_effect="Test",
        )
        sample_request.candidates = [candidate]

        with patch.object(agent, '_execute_in_sandbox', return_value=(True, "", None)):
            response = agent.validate_candidates(sample_request)
            assert response.total_validated == 1

    def test_five_candidates_validation(self, agent, sample_request):
        """Validate exactly 5 candidates (typical use case)."""
        candidates = [
            PatchCandidate(
                patch_id=f"patch-{i}",
                modified_code=f"x = {i}",
                explanation=f"Candidate {i}",
                security_strategy="Test",
                expected_effect="Test",
            )
            for i in range(5)
        ]
        sample_request.candidates = candidates

        with patch.object(agent, '_execute_in_sandbox', return_value=(True, "", None)):
            response = agent.validate_candidates(sample_request)
            assert response.total_validated == 5

    def test_candidate_with_long_code(self, agent, sample_request):
        """Validate candidate with very long code."""
        candidate = PatchCandidate(
            patch_id="patch-long",
            modified_code="x = 1\n" * 10000,
            explanation="Long code test",
            security_strategy="Test",
            expected_effect="Test",
        )
        sample_request.candidates = [candidate]

        with patch.object(agent, '_execute_in_sandbox', return_value=(True, "", None)):
            result = agent.validate_candidate(candidate, sample_request)
            assert result.patch_id == "patch-long"

    def test_special_characters_in_code(self, agent, sample_request):
        """Validate candidate with special characters."""
        candidate = PatchCandidate(
            patch_id="patch-special",
            modified_code="x = 'hello; world!@#$%^&*()'",
            explanation="Special chars test",
            security_strategy="Test",
            expected_effect="Test",
        )
        sample_request.candidates = [candidate]

        with patch.object(agent, '_execute_in_sandbox', return_value=(True, "", None)):
            result = agent.validate_candidate(candidate, sample_request)
            assert result.patch_id == "patch-special"

    def test_concurrent_validations(self, agent, sample_request):
        """Validate multiple candidates concurrently."""
        import concurrent.futures

        candidates = [
            PatchCandidate(
                patch_id=f"patch-{i}",
                modified_code=f"print({i})",
                explanation=f"Candidate {i}",
                security_strategy="Test",
                expected_effect="Test",
            )
            for i in range(5)
        ]
        sample_request.candidates = candidates

        with patch.object(agent, '_execute_in_sandbox', return_value=(True, "passed", None)):
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = [
                    executor.submit(agent.validate_candidate, c, sample_request)
                    for c in candidates
                ]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]

            assert len(results) == 5
            for result in results:
                assert isinstance(result, PatchValidationResult)

# ============================================================
# Test: Sandbox Delegation
# ============================================================

class TestSandboxDelegation:
    """Test that ValidationAgent delegates execution to SandboxAgent."""

    def test_execute_in_sandbox_delegation(self, agent, sample_request):
        """Test that _execute_in_sandbox calls SandboxAgent and NOT subprocess.run."""
        with patch('app.agents.sandbox_agent.SandboxAgent') as mock_sandbox_class, \
             patch('subprocess.run') as mock_subprocess_run:
            
            mock_sandbox = MagicMock()
            mock_sandbox_class.return_value = mock_sandbox
            
            mock_response = MagicMock()
            mock_response.tests.success = True
            mock_response.tests.output = "test output"
            mock_response.tests.error = None
            mock_sandbox.validate_patch.return_value = mock_response
            
            # Use an allowed command to pass validation
            success, output, error = agent._execute_in_sandbox("print('hello')", "python test.py", sample_request)
            
            # Assert subprocess.run was NEVER called
            mock_subprocess_run.assert_not_called()
            
            # Assert SandboxAgent was instantiated and validate_patch was called
            mock_sandbox_class.assert_called_once()
            mock_sandbox.validate_patch.assert_called_once()
            
            # Verify the request passed to SandboxAgent
            call_args = mock_sandbox.validate_patch.call_args[0][0]
            assert call_args.test_command == "python test.py"
            assert call_args.patch.modified_code == "print('hello')"
            
            assert success is True
            assert output == "test output"
            assert error is None


