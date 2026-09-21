"""
Regression test: Docker volume mount must not shadow runner.py.

Bug fixed: sandbox_agent.py previously mounted the host workspace to /sandbox,
which shadowed /sandbox/runner.py baked into the container image.
The container CMD 'python runner.py' failed with:
    python: can't open file '/sandbox/runner.py': No such file or directory
All patches received compilation_score=0.0 / "Could not read results" / FAIL.

Fix: workspace is now mounted to /workspace (not /sandbox).
runner.py reads inputs from /workspace/* and writes results.json to /workspace/.

These tests verify:
1. The volume mount uses /workspace (not /sandbox) as the bind target.
2. results.json is read from the host workspace path (not via exec_run).
3. A valid Python patch produces compilation.success=True.
4. The broken exec_run-on-stopped-container path is not used.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.agents.models import (
    PatchCandidate,
    SandboxConfig,
    SandboxValidationRequest,
)
from app.agents.sandbox_agent import SandboxAgent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(code: str = "print('hello')", test_cmd: str = "") -> SandboxValidationRequest:
    """Build a minimal SandboxValidationRequest for a Python patch."""
    return SandboxValidationRequest(
        patch=PatchCandidate(
            patch_id="reg-patch-1",
            modified_code=code,
            explanation="Regression test patch",
            security_strategy="none",
            expected_effect="test",
        ),
        repository_id="regression-test",
        workspace_path="",
        file_path="test.py",
        original_code="",
        language="python",
        test_command=test_cmd,
    )


def _make_results_json(compilation_success: bool = True) -> dict:
    return {
        "language": "python",
        "patch_application": {"success": True, "output": "Patch applied", "duration_ms": 10},
        "compilation": {
            "success": compilation_success,
            "output": "No compilation required",
            "duration_ms": 0,
            "language": "python",
        },
        "tests": {
            "success": True,
            "output": "No test command provided",
            "duration_ms": 0,
            "framework": "none",
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "failures": [],
        },
        "security_scan": {
            "success": True,
            "scanner": "none",
            "vulnerabilities_found": 0,
            "findings": [],
            "output": "No scan command provided",
            "duration_ms": 0,
        },
        "performance": {
            "execution_time_ms": 50,
            "memory_peak_mb": 10.0,
            "cpu_usage_percent": 0.0,
            "io_read_bytes": 0,
            "io_write_bytes": 0,
        },
        "execution_time": 50,
    }


# ---------------------------------------------------------------------------
# Test 1: Volume mount must use /workspace, not /sandbox
# ---------------------------------------------------------------------------

class TestVolumeMountPath:
    """Verify the container volume is mounted at /workspace, not /sandbox."""

    def test_workspace_mounted_at_slash_workspace(self):
        """
        The bind target must be /workspace so that /sandbox/runner.py
        (baked into the image) is not shadowed.
        """
        mock_docker = MagicMock()
        mock_docker.images.get.return_value = True

        captured_volumes = {}

        def fake_run(**kwargs):
            captured_volumes.update(kwargs.get("volumes", {}))
            container = MagicMock()
            container.id = "abc123def456"
            container.wait.return_value = {"StatusCode": 0}
            container.logs.return_value = b""
            return container

        mock_docker.containers.run.side_effect = fake_run

        agent = SandboxAgent(docker_client=mock_docker)
        request = _make_request()

        with tempfile.TemporaryDirectory() as workspace_dir:
            results_path = Path(workspace_dir) / "results.json"
            results_path.write_text(json.dumps(_make_results_json()), encoding="utf-8")

            with patch.object(agent, "_prepare_workspace", return_value=workspace_dir):
                agent.validate_patch(request)

        assert len(captured_volumes) == 1, (
            f"Expected 1 volume binding, got {len(captured_volumes)}: {captured_volumes}"
        )

        bind_targets = [v["bind"] for v in captured_volumes.values()]
        assert "/workspace" in bind_targets, (
            f"Volume must be mounted at /workspace, got: {bind_targets}. "
            "Mounting at /sandbox shadows runner.py!"
        )
        assert "/sandbox" not in bind_targets, (
            f"Volume must NOT be mounted at /sandbox (shadows runner.py): {bind_targets}"
        )

    def test_sandbox_directory_not_used_as_mount_target(self):
        """No volume may be bound to /sandbox to prevent runner.py shadowing."""
        mock_docker = MagicMock()
        mock_docker.images.get.return_value = True

        captured = {}

        def fake_run(**kwargs):
            captured.update(kwargs.get("volumes", {}))
            c = MagicMock()
            c.id = "aabbcc112233"
            c.wait.return_value = {"StatusCode": 0}
            c.logs.return_value = b""
            return c

        mock_docker.containers.run.side_effect = fake_run

        agent = SandboxAgent(docker_client=mock_docker)

        with tempfile.TemporaryDirectory() as workspace_dir:
            results_path = Path(workspace_dir) / "results.json"
            results_path.write_text(json.dumps(_make_results_json()), encoding="utf-8")

            with patch.object(agent, "_prepare_workspace", return_value=workspace_dir):
                agent.validate_patch(_make_request())

        for host_path, binding in captured.items():
            assert binding["bind"] != "/sandbox", (
                f"Host path '{host_path}' is bound to /sandbox -- "
                "this overwrites runner.py inside the container!"
            )


# ---------------------------------------------------------------------------
# Test 2: results.json is read from host workspace (not exec_run)
# ---------------------------------------------------------------------------

class TestResultsReadFromHostWorkspace:
    """Verify results.json is read from the host workspace directory."""

    def test_read_results_from_host_path(self):
        """
        _read_results_from_container should read from a host path (workspace_dir),
        not from a running container via exec_run.
        """
        mock_docker = MagicMock()
        mock_docker.images.get.return_value = True
        agent = SandboxAgent(docker_client=mock_docker)

        with tempfile.TemporaryDirectory() as workspace_dir:
            results_data = _make_results_json(compilation_success=True)
            results_path = Path(workspace_dir) / "results.json"
            results_path.write_text(json.dumps(results_data), encoding="utf-8")

            result = agent._read_results_from_container(workspace_dir)

        assert result["compilation"]["success"] is True
        assert result["compilation"]["output"] == "No compilation required"
        assert result["tests"]["success"] is True

    def test_read_results_fallback_when_missing(self):
        """
        When results.json is absent (e.g. container crashed before writing),
        _read_results_from_container must return the fallback dict, not raise.
        """
        mock_docker = MagicMock()
        mock_docker.images.get.return_value = True
        agent = SandboxAgent(docker_client=mock_docker)

        with tempfile.TemporaryDirectory() as workspace_dir:
            result = agent._read_results_from_container(workspace_dir)

        assert result["compilation"]["success"] is False
        assert "Could not read results" in result["compilation"]["output"]

    def test_no_exec_run_on_stopped_container(self):
        """
        exec_run must NOT be called on the container after container.wait() returns.
        exec_run on a stopped container raises 'container is not running'.
        """
        mock_docker = MagicMock()
        mock_docker.images.get.return_value = True

        mock_container = MagicMock()
        mock_container.id = "deadbeef000000"
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_container.logs.return_value = b"runner output"
        mock_docker.containers.run.return_value = mock_container

        agent = SandboxAgent(docker_client=mock_docker)

        with tempfile.TemporaryDirectory() as workspace_dir:
            results_path = Path(workspace_dir) / "results.json"
            results_path.write_text(json.dumps(_make_results_json()), encoding="utf-8")

            with patch.object(agent, "_prepare_workspace", return_value=workspace_dir):
                agent.validate_patch(_make_request())

        mock_container.exec_run.assert_not_called()


# ---------------------------------------------------------------------------
# Test 3: Valid patch produces compilation success through mock pipeline
# ---------------------------------------------------------------------------

class TestValidPatchProducesPass:
    """A valid Python patch must not produce FAIL due to infrastructure errors."""

    def test_valid_python_patch_compilation_success(self):
        mock_docker = MagicMock()
        mock_docker.images.get.return_value = True

        mock_container = MagicMock()
        mock_container.id = "aabbcc00112233"
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_container.logs.return_value = b""
        mock_docker.containers.run.return_value = mock_container

        agent = SandboxAgent(docker_client=mock_docker)

        with tempfile.TemporaryDirectory() as workspace_dir:
            results_path = Path(workspace_dir) / "results.json"
            results_path.write_text(
                json.dumps(_make_results_json(compilation_success=True)),
                encoding="utf-8",
            )

            with patch.object(agent, "_prepare_workspace", return_value=workspace_dir):
                response = agent.validate_patch(_make_request())

        assert response.compilation.success is True, (
            f"Expected compilation.success=True, got False. "
            f"output={response.compilation.output!r}. "
            "This indicates the volume-mount bug may have returned."
        )
        assert response.overall_success is True

    def test_failed_patch_still_reports_failure(self):
        """A genuinely failed patch must still report failure -- no silent promotion."""
        mock_docker = MagicMock()
        mock_docker.images.get.return_value = True

        mock_container = MagicMock()
        mock_container.id = "failfailfail"
        mock_container.wait.return_value = {"StatusCode": 1}
        mock_container.logs.return_value = b"SyntaxError: invalid syntax"
        mock_docker.containers.run.return_value = mock_container

        agent = SandboxAgent(docker_client=mock_docker)

        with tempfile.TemporaryDirectory() as workspace_dir:
            fail_results = _make_results_json(compilation_success=False)
            fail_results["compilation"]["output"] = "SyntaxError: invalid syntax"
            (Path(workspace_dir) / "results.json").write_text(
                json.dumps(fail_results), encoding="utf-8"
            )

            with patch.object(agent, "_prepare_workspace", return_value=workspace_dir):
                response = agent.validate_patch(_make_request())

        assert response.compilation.success is False


# ---------------------------------------------------------------------------
# Test 4: _prepare_workspace writes all required input files
# ---------------------------------------------------------------------------

class TestPrepareWorkspace:
    """Verify _prepare_workspace writes all files runner.py needs."""

    def test_prepare_workspace_creates_required_files(self):
        mock_docker = MagicMock()
        mock_docker.images.get.return_value = True
        agent = SandboxAgent(docker_client=mock_docker)

        request = SandboxValidationRequest(
            patch=PatchCandidate(
                patch_id="ws-test-1",
                modified_code="print('patched')",
                explanation="test",
                security_strategy="none",
                expected_effect="test",
            ),
            repository_id="test-repo",
            workspace_path="",
            file_path="test.py",
            original_code="print('original')",
            language="python",
            test_command="pytest test.py",
            compile_command="",
            scan_command="semgrep --config=auto test.py",
        )

        workspace_dir = agent._prepare_workspace(request)

        try:
            ws = Path(workspace_dir)
            assert (ws / "patch.py").exists()
            assert (ws / "target_file").exists()
            assert (ws / "original_code").exists()
            assert (ws / "language").exists()
            assert (ws / "test_cmd").exists()
            assert (ws / "scan_cmd").exists()

            assert (ws / "patch.py").read_text(encoding="utf-8") == "print('patched')"
            assert (ws / "target_file").read_text(encoding="utf-8") == "test.py"
            assert (ws / "language").read_text(encoding="utf-8") == "python"
            assert (ws / "test_cmd").read_text(encoding="utf-8") == "pytest test.py"
        finally:
            import shutil
            shutil.rmtree(workspace_dir, ignore_errors=True)
