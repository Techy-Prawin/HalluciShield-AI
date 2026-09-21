"""
HalluciShield Isolated Code Runner
Executes untrusted candidate patches safely inside Docker container.

Pipeline:
1. Repository preparation - clone/prepare repo with patch applied
2. Patch application - apply the candidate patch to the target file
3. Compilation - compile the code if applicable
4. Test execution - run the test suite
5. Scanner execution - run security scanner (semgrep)
6. Result collection - collect all results into structured JSON
7. Cleanup - automatic container teardown
"""

import json
import os
import subprocess
import sys
import time
import traceback
from pathlib import Path


# /workspace is either a bind-mounted directory or populated through Docker's
# archive API when the AI engine itself is running in a container.
WORKSPACE_DIR = Path(os.getenv("SANDBOX_WORKSPACE_DIR", "/workspace"))
WORK_DIR = WORKSPACE_DIR / "workspace"
RESULTS_FILE = WORKSPACE_DIR / "results.json"
PATCH_FILE = WORKSPACE_DIR / "patch.py"
TARGET_FILE = WORKSPACE_DIR / "target_file"
ORIGINAL_CODE_FILE = WORKSPACE_DIR / "original_code"
LANGUAGE_FILE = WORKSPACE_DIR / "language"
COMPILE_CMD_FILE = WORKSPACE_DIR / "compile_cmd"
TEST_CMD_FILE = WORKSPACE_DIR / "test_cmd"
SCAN_CMD_FILE = WORKSPACE_DIR / "scan_cmd"


def run_command(cmd: str, timeout: int = 30, cwd: str = None) -> dict:
    """Run a shell command with timeout and capture output."""
    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd or str(WORK_DIR),
        )
        duration_ms = int((time.time() - start) * 1000)
        return {
            "success": result.returncode == 0,
            "output": (result.stdout + result.stderr).strip()[:10000],
            "duration_ms": duration_ms,
            "return_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "output": f"Command timed out after {timeout}s",
            "duration_ms": int((time.time() - start) * 1000),
            "return_code": -1,
        }
    except Exception as e:
        return {
            "success": False,
            "output": str(e),
            "duration_ms": int((time.time() - start) * 1000),
            "return_code": -1,
        }


def read_file(path: Path) -> str:
    """Read file content, return empty string if not found."""
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def prepare_repository():
    """Step 1: Prepare the repository workspace."""
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    # Read configuration files
    language = read_file(LANGUAGE_FILE).strip().lower() or "python"
    compile_cmd = read_file(COMPILE_CMD_FILE).strip()
    test_cmd = read_file(TEST_CMD_FILE).strip()
    scan_cmd = read_file(SCAN_CMD_FILE).strip()

    return {
        "language": language,
        "compile_command": compile_cmd,
        "test_command": test_cmd,
        "scan_command": scan_cmd,
    }


def apply_patch() -> dict:
    """Step 2: Apply the candidate patch to the target file."""
    start = time.time()
    patch_code = read_file(PATCH_FILE)
    target_file = read_file(TARGET_FILE).strip()
    original_code = read_file(ORIGINAL_CODE_FILE)

    if not patch_code.strip():
        return {"success": False, "output": "No patch code provided", "duration_ms": 0}

    if not target_file:
        return {"success": False, "output": "No target file path provided", "duration_ms": 0}

    # --- SECURITY (CRIT-2): Validate target path stays within WORK_DIR ---
    try:
        target_path = (WORK_DIR / target_file).resolve()
        work_dir_resolved = WORK_DIR.resolve()
        # Path must be strictly inside WORK_DIR (not equal to it, and not above it)
        if not str(target_path).startswith(str(work_dir_resolved) + os.sep):
            return {
                "success": False,
                "output": (
                    f"SECURITY: Rejected path traversal attempt. "
                    f"target_file='{target_file}' resolved to '{target_path}' "
                    f"which is outside workspace '{work_dir_resolved}'."
                ),
                "duration_ms": 0,
            }
    except Exception as e:
        return {"success": False, "output": f"Path validation error: {e}", "duration_ms": 0}
    # --- End security check ---

    target_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Write original code if provided
        if original_code.strip():
            target_path.write_text(original_code, encoding="utf-8")

        # Write the patched code
        target_path.write_text(patch_code, encoding="utf-8")

        duration_ms = int((time.time() - start) * 1000)
        return {
            "success": True,
            "output": f"Patch applied to {target_file}",
            "duration_ms": duration_ms,
        }
    except Exception as e:
        return {
            "success": False,
            "output": f"Failed to apply patch: {str(e)}",
            "duration_ms": int((time.time() - start) * 1000),
        }


def compile_code(compile_cmd: str) -> dict:
    """Step 3: Compile the code if a compile command is provided."""
    if not compile_cmd:
        return {
            "success": True,
            "output": "No compilation required",
            "duration_ms": 0,
            "language": "",
        }

    language = read_file(LANGUAGE_FILE).strip().lower() or "python"
    result = run_command(compile_cmd, timeout=30)
    return {
        "success": result["success"],
        "output": result["output"],
        "duration_ms": result["duration_ms"],
        "language": language,
    }


def run_tests(test_cmd: str) -> dict:
    """Step 4: Execute the test suite."""
    if not test_cmd:
        return {
            "success": True,
            "output": "No test command provided",
            "duration_ms": 0,
            "framework": "",
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "failures": [],
        }

    result = run_command(test_cmd, timeout=30)

    # Parse test output for common frameworks
    output = result["output"]
    framework = "unknown"
    total_tests = 0
    passed = 0
    failed = 0
    skipped = 0
    failures = []

    if "pytest" in test_cmd or "=== " in output:
        framework = "pytest"
        for line in output.split("\n"):
            if "passed" in line or "failed" in line:
                parts = line.split("==")[1].strip().rstrip(".").split(",") if "==" in line else []
                for part in parts:
                    part = part.strip()
                    if "passed" in part:
                        passed = int(part.split()[0])
                    elif "failed" in part:
                        failed = int(part.split()[0])
                    elif "skipped" in part:
                        skipped = int(part.split()[0])
            elif "FAILED" in line:
                failures.append({"test": line.strip()})
        total_tests = passed + failed + skipped
    elif "jest" in test_cmd or "PASS" in output or "FAIL" in output:
        framework = "jest"
        for line in output.split("\n"):
            if "Tests:" in line:
                parts = line.split("Tests:")[1].strip()
                for part in parts.split(","):
                    part = part.strip()
                    if "passed" in part:
                        passed = int(part.split()[0])
                    elif "failed" in part:
                        failed = int(part.split()[0])
                    elif "skipped" in part:
                        skipped = int(part.split()[0])
        total_tests = passed + failed + skipped
    elif "junit" in test_cmd or "Tests run:" in output:
        framework = "junit"
        for line in output.split("\n"):
            if "Tests run:" in line:
                parts = line.split("Tests run:")[1].strip()
                for part in parts.split(","):
                    part = part.strip()
                    if "Run:" in part or "run" in part.lower():
                        try:
                            total_tests = int(part.split()[0])
                        except ValueError:
                            pass
                    elif "Failures:" in part:
                        try:
                            failed = int(part.split()[0])
                        except ValueError:
                            pass
                    elif "Skipped:" in part:
                        try:
                            skipped = int(part.split()[0])
                        except ValueError:
                            pass
        passed = total_tests - failed - skipped

    return {
        "success": result["success"],
        "framework": framework,
        "total_tests": total_tests,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "output": result["output"],
        "duration_ms": result["duration_ms"],
        "failures": failures,
    }


def run_security_scan(scan_cmd: str) -> dict:
    """Step 5: Execute security scanner."""
    if not scan_cmd:
        return {
            "success": True,
            "scanner": "none",
            "vulnerabilities_found": 0,
            "findings": [],
            "output": "No scan command provided",
            "duration_ms": 0,
        }

    result = run_command(scan_cmd, timeout=30)
    output = result["output"]

    # Parse semgrep output if applicable
    findings = []
    vuln_count = 0
    scanner = "unknown"

    if "semgrep" in scan_cmd:
        scanner = "semgrep"
        try:
            # Try to parse semgrep JSON output
            json_start = output.find("[")
            json_end = output.rfind("]") + 1
            if json_start >= 0 and json_end > json_start:
                findings = json.loads(output[json_start:json_end])
                vuln_count = len(findings)
        except (json.JSONDecodeError, ValueError):
            # Fall back to counting error lines
            for line in output.split("\n"):
                if "error" in line.lower() or "warning" in line.lower():
                    vuln_count += 1
                    findings.append({"message": line.strip()})

    return {
        "success": result["success"],
        "scanner": scanner,
        "vulnerabilities_found": vuln_count,
        "findings": findings[:100],
        "output": result["output"][:5000],
        "duration_ms": result["duration_ms"],
    }


def measure_performance() -> dict:
    """Step 6: Measure performance metrics."""
    # Read /proc/self/status for memory info
    memory_peak = 0.0
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if "VmHWM" in line:
                    memory_peak = float(line.split()[1]) / 1024  # Convert to MB
                    break
    except Exception:
        pass

    return {
        "execution_time_ms": 0,
        "memory_peak_mb": memory_peak,
        "cpu_usage_percent": 0.0,
        "io_read_bytes": 0,
        "io_write_bytes": 0,
    }


def main():
    """Main validation pipeline."""
    overall_start = time.time()
    results = {}

    try:
        # Step 1: Prepare repository
        config = prepare_repository()
        results["language"] = config["language"]

        # Step 2: Apply patch
        patch_result = apply_patch()
        results["patch_application"] = patch_result

        if not patch_result["success"]:
            results["compilation"] = {"success": False, "output": "Patch application failed", "duration_ms": 0, "language": config["language"]}
            results["tests"] = {"success": False, "output": "Patch application failed", "duration_ms": 0, "framework": "", "total_tests": 0, "passed": 0, "failed": 0, "skipped": 0, "failures": []}
            results["security_scan"] = {"success": False, "scanner": "none", "vulnerabilities_found": 0, "findings": [], "output": "Patch application failed", "duration_ms": 0}
            results["performance"] = measure_performance()
            results["execution_time"] = int((time.time() - overall_start) * 1000)
            _write_results(results)
            return

        # Step 3: Compile
        compile_result = compile_code(config["compile_command"])
        results["compilation"] = compile_result

        # Step 4: Run tests
        test_result = run_tests(config["test_command"])
        results["tests"] = test_result

        # Step 5: Security scan
        scan_result = run_security_scan(config["scan_command"])
        results["security_scan"] = scan_result

        # Step 6: Performance
        results["performance"] = measure_performance()

    except Exception as e:
        results["error"] = traceback.format_exc()
        results["compilation"] = {"success": False, "output": str(e), "duration_ms": 0, "language": ""}
        results["tests"] = {"success": False, "output": str(e), "duration_ms": 0, "framework": "", "total_tests": 0, "passed": 0, "failed": 0, "skipped": 0, "failures": []}
        results["security_scan"] = {"success": False, "scanner": "none", "vulnerabilities_found": 0, "findings": [], "output": str(e), "duration_ms": 0}
        results["performance"] = measure_performance()

    results["execution_time"] = int((time.time() - overall_start) * 1000)
    _write_results(results)


def _write_results(results: dict):
    """Write results to JSON file."""
    try:
        RESULTS_FILE.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    except Exception as e:
        print(f"[Sandbox] Failed to write results: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
