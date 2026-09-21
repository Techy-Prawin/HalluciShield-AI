"""
Secure Patch Validation Sandbox Agent for HalluciShield AI.

Creates isolated Docker containers to test candidate patches.
Each candidate patch runs in its own isolated container with strict resource limits.

Security guarantees:
- Network isolation (--net=none)
- Non-root user execution (UID 10001)
- CPU limit (default 1.0 core)
- Memory limit (default 512MB)
- Execution timeout (default 30s)
- Temporary filesystem (tmpfs)
- Process limits (default 64)
- Automatic container cleanup on completion or failure
- Never executes uploaded code directly on the host

IMPORTANT: This sandbox does NOT validate patches for correctness.
It only runs them in isolation and reports results.
"""

import json
import io
import logging
import os
import shutil
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Optional

from app.agents.models import (
    CompilationResult,
    PerformanceResult,
    PatchCandidate,
    SandboxConfig,
    SandboxValidationRequest,
    SandboxValidationResponse,
    SecurityScanResult,
    TestResult,
)

logger = logging.getLogger(__name__)

DEFAULT_SANDBOX_IMAGE = os.getenv("SANDBOX_IMAGE", "hallucishield-sandbox:latest")
SANDBOX_DIR = Path(__file__).parent.parent.parent / "sandbox"


class SandboxAgent:
    """
    Secure Patch Validation Sandbox Agent.

    Orchestrates isolated Docker containers to validate candidate patches.
    Each patch runs in its own container with strict resource limits.
    """

    def __init__(self, docker_client=None, image_name: str = DEFAULT_SANDBOX_IMAGE):
        self.image_name = image_name
        self._docker = docker_client
        self._ensure_image()

    def _get_docker(self):
        """Lazy-load Docker client."""
        if self._docker is None:
            try:
                import docker
                self._docker = docker.from_env()
            except Exception as e:
                logger.error(f"[Sandbox] Docker client initialization failed: {e}")
                raise RuntimeError(
                    "Docker is not available. Please install Docker and ensure it is running."
                )
        return self._docker

    def is_available(self) -> bool:
        """Probe whether the Docker sandbox can be created right now."""
        try:
            self._get_docker()
            return True
        except Exception as e:
            logger.info(f"[Sandbox] Sandbox unavailable: {e}")
            return False

    def _ensure_image(self):
        """Build sandbox image if it doesn't exist."""
        try:
            client = self._get_docker()
            try:
                client.images.get(self.image_name)
                logger.debug(f"[Sandbox] Image {self.image_name} already exists")
            except Exception:
                logger.info(f"[Sandbox] Building sandbox image {self.image_name}...")
                if SANDBOX_DIR.exists():
                    client.images.build(
                        path=str(SANDBOX_DIR),
                        tag=self.image_name,
                        dockerfile="Dockerfile.sandbox",
                    )
                    logger.info(f"[Sandbox] Built image {self.image_name}")
                else:
                    logger.warning(f"[Sandbox] Sandbox directory not found at {SANDBOX_DIR}")
        except Exception as e:
            logger.warning(f"[Sandbox] Could not ensure image: {e}")

    def validate_patch(self, request: SandboxValidationRequest) -> SandboxValidationResponse:
        """
        Validate a single candidate patch in an isolated Docker container.

        Pipeline:
        1. Prepare workspace with patch and configuration files
        2. Create isolated container with strict resource limits
        3. Execute validation pipeline inside container
        4. Collect results
        5. Automatic container cleanup

        Args:
            request: SandboxValidationRequest with patch and configuration

        Returns:
            SandboxValidationResponse with validation results
        """
        logger.info(f"[Sandbox] Starting validation for patch {request.patch.patch_id}")
        overall_start = time.time()
        config = request.sandbox_config or SandboxConfig()
        container = None
        workspace_dir = None
        container_id = None

        try:
            # Step 1: Prepare workspace
            workspace_dir = self._prepare_workspace(request)
            logger.debug(f"[Sandbox] Workspace prepared at {workspace_dir}")

            # Step 2: Create and run container
            container = self._create_container(workspace_dir, config)
            container_id = container.id
            logger.info(f"[Sandbox] Created container {container_id[:12]}")

            # Step 3: Execute validation pipeline
            results = self._execute_pipeline(container, config, workspace_dir)
            logger.debug(f"[Sandbox] Pipeline completed for {container_id[:12]}")

            # Step 4: Parse results
            response = self._parse_results(request, results, container_id)
            response.validation_duration_ms = int((time.time() - overall_start) * 1000)
            response.overall_success = (
                response.compilation.success
                and response.tests.success
                and response.security_scan.success
            )

            logger.info(
                f"[Sandbox] Validation complete for {request.patch.patch_id}: "
                f"overall={response.overall_success}, "
                f"compilation={response.compilation.success}, "
                f"tests={response.tests.success}, "
                f"security={response.security_scan.success}"
            )

            return response

        except Exception as e:
            logger.error(f"[Sandbox] Validation failed: {e}", exc_info=True)
            return SandboxValidationResponse(
                patch_id=request.patch.patch_id,
                compilation=CompilationResult(success=False, error=str(e)),
                tests=TestResult(success=False, error=str(e)),
                security_scan=SecurityScanResult(success=False, error=str(e)),
                performance=PerformanceResult(),
                overall_success=False,
                validation_duration_ms=int((time.time() - overall_start) * 1000),
                sandbox_security_notes=[f"Validation error: {str(e)}"],
            )
        finally:
            # Step 5: Automatic container cleanup
            self._cleanup_container(container)
            self._cleanup_workspace(workspace_dir)

    def _prepare_workspace(self, request: SandboxValidationRequest) -> str:
        """Prepare isolated workspace directory with patch and configuration.

        Security (CRIT-2): validates file_path for path traversal before
        writing it into the workspace config. The sandbox runner performs
        a second boundary check when it actually writes the patched file.
        """
        import posixpath

        # --- SECURITY: validate file_path before persisting it ---
        raw_file_path = request.file_path
        # Reject absolute paths
        if posixpath.isabs(raw_file_path) or os.path.isabs(raw_file_path):
            raise ValueError(
                f"[Sandbox] SECURITY: file_path must be a relative path, "
                f"got absolute: '{raw_file_path}'"
            )
        # Reject any path component that is '..' (traversal)
        normalized = posixpath.normpath(raw_file_path)
        for part in normalized.replace("\\", "/").split("/"):
            if part == "..":
                raise ValueError(
                    f"[Sandbox] SECURITY: file_path contains path traversal: '{raw_file_path}'"
                )
        # --- End security check ---

        workspace = tempfile.mkdtemp(prefix="hallucishield_sandbox_")

        # Write patch code
        patch_file = Path(workspace) / "patch.py"
        patch_file.write_text(request.patch.modified_code, encoding="utf-8")

        # Write target file path (now validated above)
        target_file = Path(workspace) / "target_file"
        target_file.write_text(raw_file_path, encoding="utf-8")

        # Write original code
        original_code_file = Path(workspace) / "original_code"
        original_code_file.write_text(request.original_code, encoding="utf-8")

        # Write language
        language_file = Path(workspace) / "language"
        language_file.write_text(request.language, encoding="utf-8")

        # Write commands
        if request.compile_command:
            compile_file = Path(workspace) / "compile_cmd"
            compile_file.write_text(request.compile_command, encoding="utf-8")

        if request.test_command:
            test_file = Path(workspace) / "test_cmd"
            test_file.write_text(request.test_command, encoding="utf-8")

        if request.scan_command:
            scan_file = Path(workspace) / "scan_cmd"
            scan_file.write_text(request.scan_command, encoding="utf-8")

        return workspace

    def _create_container(self, workspace_dir: str, config: SandboxConfig):
        """Create an isolated Docker container with strict resource limits."""
        client = self._get_docker()

        # Parse memory limit to bytes for docker-py
        memory_limit = self._parse_memory_limit(config.memory_limit)

        options = dict(
            image=self.image_name,
            command="python runner.py",
            # Security: Network isolation
            network_disabled=True,
            # Security: Non-root user (enforced by Dockerfile)
            # Resource limits
            mem_limit=memory_limit,
            cpu_quota=int(config.cpu_limit * 100000),
            cpu_period=100000,
            pids_limit=config.max_processes,
            # Temporary filesystem
            tmpfs={
                "/tmp": f"size={config.tmpfs_size}",
                "/var/tmp": f"size={config.tmpfs_size}",
            },
            # Read-only root filesystem where possible
            read_only=False,
            # Security options
            security_opt=["no-new-privileges"],
            # Capabilities dropped
            cap_drop=["ALL"],
            # Labels for tracking
            labels={
                "hallucishield": "sandbox",
                "patch-validation": "true",
            },
        )

        if not self._uses_archive_transfer():
            # Local Docker mode can use a direct bind mount. The container mode
            # below cannot: its Docker daemon sees host paths, not paths inside
            # the AI-engine container.
            options["volumes"] = {
                workspace_dir: {"bind": "/workspace", "mode": "rw"}
            }
            return client.containers.run(detach=True, **options)

        container = client.containers.create(**options)
        self._copy_workspace_to_container(container, workspace_dir)
        container.start()
        return container

    @staticmethod
    def _uses_archive_transfer() -> bool:
        return os.getenv("SANDBOX_USE_ARCHIVE_TRANSFER", "false").lower() in {
            "1", "true", "yes", "on"
        }

    @staticmethod
    def _copy_workspace_to_container(container, workspace_dir: str) -> None:
        """Copy input files into a container without relying on host paths."""
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for path in Path(workspace_dir).iterdir():
                archive.add(path, arcname=path.name)
        stream.seek(0)
        if not container.put_archive("/workspace", stream):
            raise RuntimeError("Docker failed to copy sandbox inputs into container")

    def _execute_pipeline(self, container, config: SandboxConfig, workspace_dir: str) -> dict:
        """Execute the validation pipeline inside the container."""
        try:
            # Wait for container to finish with timeout
            result = container.wait(timeout=config.execution_timeout)
            exit_code = result.get("StatusCode", -1)

            # Get container logs
            logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")

            # Read results.json from the host-side workspace directory.
            # This is safe because the workspace is bind-mounted to /workspace inside
            # the container, so results.json written by runner.py is visible on the host.
            # We do NOT use container.exec_run() because exec cannot run on a stopped container.
            results = self._read_results_from_container(workspace_dir, container)

            results["exit_code"] = exit_code
            results["container_logs"] = logs[:10000]

            return results

        except Exception as e:
            # Container timed out or failed
            logger.warning(f"[Sandbox] Container execution failed: {e}")
            return {
                "exit_code": -1,
                "error": str(e),
                "compilation": {"success": False, "output": f"Container error: {str(e)}", "duration_ms": 0, "language": ""},
                "tests": {"success": False, "output": f"Container error: {str(e)}", "duration_ms": 0, "framework": "", "total_tests": 0, "passed": 0, "failed": 0, "skipped": 0, "failures": []},
                "security_scan": {"success": False, "scanner": "none", "vulnerabilities_found": 0, "findings": [], "output": f"Container error: {str(e)}", "duration_ms": 0},
                "performance": {"execution_time_ms": 0, "memory_peak_mb": 0, "cpu_usage_percent": 0, "io_read_bytes": 0, "io_write_bytes": 0},
            }

    def _read_results_from_container(self, workspace_dir: str, container=None) -> dict:
        """
        Read results.json written by runner.py from the host-side workspace directory.

        The workspace is bind-mounted as /workspace inside the container.
        runner.py writes /workspace/results.json, which is directly accessible
        on the host at workspace_dir/results.json after the container exits.

        We do NOT use container.exec_run() because Docker rejects exec on stopped
        containers ('container is not running'), which is precisely the state the
        container is in after container.wait() returns.
        """
        results_path = Path(workspace_dir) / "results.json"
        try:
            return json.loads(results_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.debug(f"[Sandbox] Could not read results from workspace {results_path}: {e}")

        if self._uses_archive_transfer() and container is not None:
            try:
                archive_stream, _ = container.get_archive("/workspace/results.json")
                archive_bytes = b"".join(archive_stream)
                with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
                    result_file = archive.extractfile("results.json")
                    if result_file is not None:
                        return json.loads(result_file.read().decode("utf-8"))
            except Exception as e:
                logger.debug(f"[Sandbox] Could not copy results from container: {e}")

        # Keep compatibility with container adapters that expose the result
        # stream but do not materialize the bind mount on the host.
        if container is not None:
            try:
                exit_code, output = container.exec_run("cat /workspace/results.json")
                if exit_code == 0:
                    return json.loads(output.decode("utf-8"))
            except Exception as e:
                logger.debug(f"[Sandbox] Could not read results through container adapter: {e}")

        return {
            "compilation": {"success": False, "output": "Could not read results", "duration_ms": 0, "language": ""},
            "tests": {"success": False, "output": "Could not read results", "duration_ms": 0, "framework": "", "total_tests": 0, "passed": 0, "failed": 0, "skipped": 0, "failures": []},
            "security_scan": {"success": False, "scanner": "none", "vulnerabilities_found": 0, "findings": [], "output": "Could not read results", "duration_ms": 0},
            "performance": {"execution_time_ms": 0, "memory_peak_mb": 0, "cpu_usage_percent": 0, "io_read_bytes": 0, "io_write_bytes": 0},
        }

    def _parse_results(
        self,
        request: SandboxValidationRequest,
        results: dict,
        container_id: str,
    ) -> SandboxValidationResponse:
        """Parse container results into structured response."""
        comp_data = results.get("compilation", {})
        test_data = results.get("tests", {})
        scan_data = results.get("security_scan", {})
        perf_data = results.get("performance", {})

        compilation = CompilationResult(
            success=comp_data.get("success", False),
            language=comp_data.get("language", request.language),
            output=comp_data.get("output", "")[:5000],
            duration_ms=comp_data.get("duration_ms", 0),
            error=comp_data.get("error"),
        )

        tests = TestResult(
            success=test_data.get("success", False),
            framework=test_data.get("framework", ""),
            total_tests=test_data.get("total_tests", 0),
            passed=test_data.get("passed", 0),
            failed=test_data.get("failed", 0),
            skipped=test_data.get("skipped", 0),
            output=test_data.get("output", "")[:5000],
            duration_ms=test_data.get("duration_ms", 0),
            failures=test_data.get("failures", []),
            error=test_data.get("error"),
        )

        security_scan = SecurityScanResult(
            success=scan_data.get("success", False),
            scanner=scan_data.get("scanner", "none"),
            vulnerabilities_found=scan_data.get("vulnerabilities_found", 0),
            findings=scan_data.get("findings", []),
            output=scan_data.get("output", "")[:5000],
            duration_ms=scan_data.get("duration_ms", 0),
            error=scan_data.get("error"),
        )

        performance = PerformanceResult(
            execution_time_ms=perf_data.get("execution_time_ms", 0),
            memory_peak_mb=perf_data.get("memory_peak_mb", 0.0),
            cpu_usage_percent=perf_data.get("cpu_usage_percent", 0.0),
            io_read_bytes=perf_data.get("io_read_bytes", 0),
            io_write_bytes=perf_data.get("io_write_bytes", 0),
            details=perf_data.get("details", {}),
        )

        sandbox_cfg = request.sandbox_config or SandboxConfig()
        security_notes = [
            "Container executed with --net=none (network isolated)",
            "Container executed as non-root user (UID 10001)",
            f"CPU limit: {sandbox_cfg.cpu_limit} cores",
            f"Memory limit: {sandbox_cfg.memory_limit}",
            f"Timeout: {sandbox_cfg.execution_timeout}s",
            f"Process limit: {sandbox_cfg.max_processes}",
            "tmpfs mounts for /tmp and /var/tmp",
            "No-new-privileges security option enabled",
            "All Linux capabilities dropped",
            "Automatic container cleanup on completion",
        ]

        return SandboxValidationResponse(
            patch_id=request.patch.patch_id,
            compilation=compilation,
            tests=tests,
            security_scan=security_scan,
            performance=performance,
            execution_time=results.get("execution_time", 0),
            container_id=container_id,
            sandbox_security_notes=security_notes,
        )

    def _cleanup_container(self, container):
        """Force remove container to ensure cleanup."""
        if container is None:
            return
        try:
            container.remove(force=True)
            logger.debug(f"[Sandbox] Cleaned up container {container.id[:12]}")
        except Exception as e:
            logger.warning(f"[Sandbox] Container cleanup failed: {e}")

    def _cleanup_workspace(self, workspace_dir: Optional[str]):
        """Remove temporary workspace directory."""
        if workspace_dir and os.path.exists(workspace_dir):
            try:
                shutil.rmtree(workspace_dir)
                logger.debug(f"[Sandbox] Cleaned up workspace {workspace_dir}")
            except Exception as e:
                logger.warning(f"[Sandbox] Workspace cleanup failed: {e}")

    @staticmethod
    def _parse_memory_limit(limit_str: str) -> int:
        """Parse memory limit string to bytes."""
        limit_str = limit_str.strip().lower()
        multipliers = {"k": 1024, "m": 1024**2, "g": 1024**3}
        if limit_str[-1] in multipliers:
            return int(float(limit_str[:-1]) * multipliers[limit_str[-1]])
        return int(limit_str)

    def validate_patches_batch(
        self,
        request: SandboxValidationRequest,
        candidates: list,
    ) -> list:
        """
        Validate multiple patch candidates sequentially.

        Args:
            request: Base SandboxValidationRequest (patch field will be overridden)
            candidates: List of PatchCandidate to validate

        Returns:
            List of SandboxValidationResponse for each candidate
        """
        responses = []
        for candidate in candidates:
            batch_request = SandboxValidationRequest(
                patch=candidate,
                repository_id=request.repository_id,
                workspace_path=request.workspace_path,
                file_path=request.file_path,
                original_code=request.original_code,
                language=request.language,
                test_command=request.test_command,
                compile_command=request.compile_command,
                scan_command=request.scan_command,
                sandbox_config=request.sandbox_config,
            )
            response = self.validate_patch(batch_request)
            responses.append(response)
        return responses
