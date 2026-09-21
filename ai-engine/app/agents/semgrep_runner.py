"""
Semgrep Runner and Result Parser for HalluciShield Security Analysis Agent.

Handles safe execution of Semgrep scans and parsing of results into
normalized vulnerability formats. Semgrep is the primary scanner;
LLM may later be used for reasoning and contextual analysis.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from typing import Dict, Any, List, Optional, Tuple

from app.agents.models import (
    SemgrepScanResult,
    VulnerabilitySeverity,
    VulnerabilityType,
)

logger = logging.getLogger(__name__)

# Mapping from Semgrep severity to normalized severity
SEMGREP_SEVERITY_MAP = {
    "ERROR": VulnerabilitySeverity.HIGH,
    "WARNING": VulnerabilitySeverity.MEDIUM,
    "INFO": VulnerabilitySeverity.LOW,
    "CRITICAL": VulnerabilitySeverity.CRITICAL,
}

# CWE mapping from Semgrep rule IDs
CWE_MAPPING: Dict[str, str] = {
    # SQL Injection
    "python.lang.security.sql-injection": "CWE-89",
    "javascript.lang.security.audit.dangerous-sql": "CWE-89",
    "typescript.lang.security.dangerous-sql": "CWE-89",
    "sql-injection": "CWE-89",
    "sql_injection": "CWE-89",
    # Cross-Site Scripting
    "javascript.lang.security.audit.xss": "CWE-79",
    "xss": "CWE-79",
    "cross-site-scripting": "CWE-79",
    "xss-ssrf": "CWE-79",
    # Hardcoded Secrets
    "hardcoded-password": "CWE-798",
    "hardcoded-secret": "CWE-798",
    "hardcoded-credentials": "CWE-798",
    "generic-secrets": "CWE-798",
    # Command Injection
    "command-injection": "CWE-78",
    "os-command-injection": "CWE-78",
    "subprocess-shell-true": "CWE-78",
    "dangerous-subprocess": "CWE-78",
    # Path Traversal
    "path-traversal": "CWE-22",
    "directory-traversal": "CWE-22",
    "path-joining": "CWE-22",
    # Insecure JWT
    "insecure-jwt": "CWE-347",
    "jwt-none-algorithm": "CWE-347",
    "insecure-deserialization": "CWE-502",
}

# Vulnerability type mapping from Semgrep patterns
VULNERABILITY_TYPE_MAPPING: Dict[str, VulnerabilityType] = {
    "sql-injection": VulnerabilityType.SQL_INJECTION,
    "sql_injection": VulnerabilityType.SQL_INJECTION,
    "dangerous-sql": VulnerabilityType.SQL_INJECTION,
    "xss": VulnerabilityType.CROSS_SITE_SCRIPTING,
    "cross-site-scripting": VulnerabilityType.CROSS_SITE_SCRIPTING,
    "hardcoded-password": VulnerabilityType.HARDCODED_SECRET,
    "hardcoded-secret": VulnerabilityType.HARDCODED_SECRET,
    "hardcoded-credentials": VulnerabilityType.HARDCODED_SECRET,
    "generic-secrets": VulnerabilityType.HARDCODED_SECRET,
    "command-injection": VulnerabilityType.COMMAND_INJECTION,
    "os-command-injection": VulnerabilityType.COMMAND_INJECTION,
    "subprocess-shell": VulnerabilityType.COMMAND_INJECTION,
    "dangerous-subprocess": VulnerabilityType.COMMAND_INJECTION,
    "path-traversal": VulnerabilityType.PATH_TRAVERSAL,
    "directory-traversal": VulnerabilityType.PATH_TRAVERSAL,
    "path-joining": VulnerabilityType.PATH_TRAVERSAL,
    "insecure-jwt": VulnerabilityType.INSECURE_JWT,
    "jwt-none-algorithm": VulnerabilityType.INSECURE_JWT,
    "insecure-deserialization": VulnerabilityType.INSECURE_DESERIALIZATION,
}


class SemgrepRunner:
    """
    Safe execution and result parsing for Semgrep security scans.

    Runs Semgrep in a subprocess with timeout and output capture.
    Does NOT use LLM for vulnerability detection - Semgrep is the scanner.
    """

    # Default Semgrep rules to run (OWASP Top 10 focused)
    DEFAULT_RULES = [
        "p/default",           # Default Semgrep rules
        "p/owasp-top-ten",     # OWASP Top 10
        "p/security-audit",    # Security audit rules
        "p/secrets",           # Secrets detection
    ]

    # File extensions to scan
    SCAN_EXTENSIONS = {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
        ".cs", ".c", ".cpp", ".h", ".hpp", ".rs", ".swift", ".kt",
    }

    def __init__(self, semgrep_path: Optional[str] = None):
        self.semgrep_path = semgrep_path or self._find_semgrep()
        self._validate_semgrep()

    def _find_semgrep(self) -> str:
        """Locate semgrep executable."""
        semgrep_path = shutil.which("semgrep")
        if semgrep_path:
            return semgrep_path
        # Try common paths
        common_paths = [
            "/usr/local/bin/semgrep",
            "/usr/bin/semgrep",
            os.path.expanduser("~/.local/bin/semgrep"),
        ]
        for path in common_paths:
            if os.path.isfile(path):
                return path
        return "semgrep"  # Fallback to PATH

    def _validate_semgrep(self):
        """Validate that semgrep is available and working."""
        try:
            result = subprocess.run(
                [self.semgrep_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                logger.info(f"[SemgrepRunner] Semgrep version: {result.stdout.strip()}")
            else:
                logger.warning(f"[SemgrepRunner] Semgrep validation warning: {result.stderr}")
        except FileNotFoundError:
            logger.info("[SemgrepRunner] Semgrep is unavailable; built-in rules fallback is active.")
        except subprocess.TimeoutExpired:
            logger.warning("[SemgrepRunner] Semgrep version check timed out.")
        except Exception as e:
            logger.warning(f"[SemgrepRunner] Semgrep validation error: {e}")

    def run_scan(
        self,
        target_path: str,
        rules: Optional[List[str]] = None,
        timeout_seconds: int = 120,
    ) -> Tuple[List[SemgrepScanResult], Dict[str, Any]]:
        """
        Run Semgrep scan on target path safely.

        Args:
            target_path: Path to directory or file to scan
            rules: Optional list of Semgrep rules to use
            timeout_seconds: Maximum time for scan in seconds

        Returns:
            Tuple of (list of scan results, scan metadata)
        """
        scan_start = time.time()
        rules = rules or self.DEFAULT_RULES

        # Validate target path
        if not os.path.exists(target_path):
            raise ValueError(f"Target path does not exist: {target_path}")

        # Check if Semgrep is available
        if not self._is_semgrep_available():
            logger.warning("[SemgrepRunner] Semgrep not available, using fallback pattern-based scanner")
            return self._fallback_scan(target_path, scan_start)

        # Build Semgrep command
        cmd = [
            self.semgrep_path,
            "--json",
            "--quiet",
            "--timeout", str(timeout_seconds),
        ]

        # Add rules
        for rule in rules:
            cmd.extend(["--config", rule])

        # Add target
        cmd.append(target_path)

        logger.info(f"[SemgrepRunner] Running scan: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 10,  # Extra buffer
                cwd=target_path if os.path.isdir(target_path) else os.path.dirname(target_path),
            )

            scan_duration_ms = int((time.time() - scan_start) * 1000)

            # Parse results
            findings = self._parse_results(result.stdout, result.stderr)

            metadata = {
                "scan_command": " ".join(cmd),
                "scan_duration_ms": scan_duration_ms,
                "exit_code": result.returncode,
                "rules_used": rules,
                "target_path": target_path,
                "stderr": result.stderr[:500] if result.stderr else None,
                "scanner": "semgrep",
            }

            logger.info(f"[SemgrepRunner] Scan completed in {scan_duration_ms}ms with {len(findings)} findings")

            return findings, metadata

        except subprocess.TimeoutExpired:
            logger.error(f"[SemgrepRunner] Scan timed out after {timeout_seconds}s")
            return [], {"error": "Scan timed out", "timeout_seconds": timeout_seconds}
        except FileNotFoundError:
            logger.error("[SemgrepRunner] Semgrep executable not found")
            return self._fallback_scan(target_path, scan_start)
        except Exception as e:
            logger.error(f"[SemgrepRunner] Scan failed: {e}", exc_info=True)
            return [], {"error": str(e)}

    def _is_semgrep_available(self) -> bool:
        """Check if Semgrep is available and working."""
        try:
            result = subprocess.run(
                [self.semgrep_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _fallback_scan(
        self, target_path: str, scan_start: float
    ) -> Tuple[List[SemgrepScanResult], Dict[str, Any]]:
        """
        Fallback pattern-based scanner when Semgrep is not available.

        Uses regex patterns to detect common vulnerabilities.
        This is a simplified scanner for testing and development.
        """
        import re

        findings: List[SemgrepScanResult] = []

        # Vulnerability patterns (simplified for fallback)
        patterns = [
            # SQL Injection
            (r'execute\s*\(\s*["\'].*\+', "sql-injection", "ERROR", "SQL injection via string concatenation"),
            (r'query\s*\(\s*["\'].*\+', "sql-injection", "ERROR", "SQL injection via string concatenation"),
            (r'\.format\s*\(.*(?:SELECT|INSERT|UPDATE|DELETE)', "sql-injection", "WARNING", "Potential SQL injection via string formatting"),
            # XSS
            (r'innerHTML\s*=', "xss", "ERROR", "XSS via innerHTML assignment"),
            (r'document\.write\s*\(', "xss", "WARNING", "Potential XSS via document.write"),
            # Hardcoded Secrets
            (r'(?:password|secret|api_key|apikey)\s*=\s*["\'][^"\']+["\']', "hardcoded-password", "WARNING", "Hardcoded secret detected"),
            (r'(?:PASSWORD|SECRET|API_KEY|APIKEY)\s*=\s*["\'][^"\']+["\']', "hardcoded-password", "ERROR", "Hardcoded secret detected"),
            # Command Injection
            (r'os\.system\s*\(', "command-injection", "ERROR", "Command injection via os.system"),
            (r'subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True', "command-injection", "ERROR", "Command injection via subprocess with shell=True"),
            # Path Traversal
            (r'open\s*\(.*\+', "path-traversal", "WARNING", "Potential path traversal via string concatenation"),
            # Insecure JWT
            (r'algorithm.*none', "insecure-jwt", "ERROR", "Insecure JWT with none algorithm"),
        ]

        # Walk through files
        for root, dirs, files in os.walk(target_path):
            # Skip hidden directories and common non-source directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'venv', '.git']]

            for file in files:
                if not any(file.endswith(ext) for ext in ['.py', '.js', '.jsx', '.ts', '.tsx', '.java']):
                    continue

                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, target_path)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    for line_num, line in enumerate(content.splitlines(), 1):
                        for pattern, rule_id, severity, message in patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append(SemgrepScanResult(
                                    rule_id=rule_id,
                                    message=message,
                                    severity=severity,
                                    file=rel_path,
                                    line=line_num,
                                    metadata={"fallback_scanner": True},
                                    extra={"line_content": line.strip()[:100]},
                                ))
                except Exception as e:
                    logger.warning(f"[SemgrepRunner] Failed to read file {file_path}: {e}")
                    continue

        scan_duration_ms = int((time.time() - scan_start) * 1000)

        metadata = {
            "scan_command": "fallback_pattern_scanner",
            "scan_duration_ms": scan_duration_ms,
            "exit_code": 0,
            "rules_used": ["fallback-patterns"],
            "target_path": target_path,
            "scanner": "fallback",
            "note": "Semgrep not available, using pattern-based fallback scanner",
        }

        logger.info(f"[SemgrepRunner] Fallback scan completed in {scan_duration_ms}ms with {len(findings)} findings")

        return findings, metadata

    def _parse_results(self, stdout: str, stderr: str) -> List[SemgrepScanResult]:
        """Parse Semgrep JSON output into normalized format."""
        findings: List[SemgrepScanResult] = []

        if not stdout or not stdout.strip():
            return findings

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            logger.warning(f"[SemgrepRunner] Failed to parse Semgrep output: {e}")
            return findings

        # Semgrep JSON format: { "results": [...], "errors": [...], ... }
        results = data.get("results", [])

        for result in results:
            try:
                finding = self._parse_single_result(result)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.warning(f"[SemgrepRunner] Failed to parse result: {e}")
                continue

        return findings

    def _parse_single_result(self, result: Dict[str, Any]) -> Optional[SemgrepScanResult]:
        """Parse a single Semgrep result into SemgrepScanResult."""
        rule_id = result.get("check_id", result.get("rule_id", "unknown"))
        message = result.get("message", "No message")
        severity_str = result.get("extra", {}).get("severity", result.get("severity", "WARNING"))
        file_path = result.get("path", result.get("file", "unknown"))
        line = result.get("start", {}).get("line", result.get("line", 0))
        end_line = result.get("end", {}).get("line")

        # Extract metadata
        metadata = result.get("metadata", {})
        extra = result.get("extra", {})

        return SemgrepScanResult(
            rule_id=rule_id,
            message=message,
            severity=severity_str,
            file=file_path,
            line=line,
            end_line=end_line,
            metadata=metadata,
            extra=extra,
        )

    def has_finding_type(self, findings: List[SemgrepScanResult], vuln_type: str) -> bool:
        """Check if findings contain a specific vulnerability type."""
        for finding in findings:
            rule_lower = finding.rule_id.lower()
            if vuln_type.lower() in rule_lower:
                return True
        return False

    def get_findings_by_severity(
        self, findings: List[SemgrepScanResult], severity: VulnerabilitySeverity
    ) -> List[SemgrepScanResult]:
        """Filter findings by normalized severity."""
        result = []
        for finding in findings:
            normalized = self._normalize_severity(finding.severity)
            if normalized == severity:
                result.append(finding)
        return result

    def _normalize_severity(self, semgrep_severity: str) -> VulnerabilitySeverity:
        """Map Semgrep severity to normalized severity."""
        return SEMGREP_SEVERITY_MAP.get(
            semgrep_severity.upper(),
            VulnerabilitySeverity.MEDIUM
        )


# Module-level singleton for reuse
semgrep_runner = SemgrepRunner()
