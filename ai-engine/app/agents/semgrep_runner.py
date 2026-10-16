"""
Semgrep Runner and Result Parser for HalluciShield Security Analysis Agent.

Handles safe execution of Semgrep scans and parsing of results into
normalized vulnerability formats. Semgrep is the primary scanner;
LLM may later be used for reasoning and contextual analysis.
Includes high-precision deterministic fallback pattern scanner with
comprehensive Java, Python, and JavaScript/TypeScript vulnerability coverage.
"""

import json
import logging
import os
import re
import shutil
import subprocess
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

# CWE mapping from Semgrep and fallback rule IDs
CWE_MAPPING: Dict[str, str] = {
    # SQL Injection
    "python.lang.security.sql-injection": "CWE-89",
    "javascript.lang.security.audit.dangerous-sql": "CWE-89",
    "typescript.lang.security.dangerous-sql": "CWE-89",
    "sql-injection": "CWE-89",
    "sql_injection": "CWE-89",
    "tainted-sql": "CWE-89",
    "sqli": "CWE-89",
    "java.sql.": "CWE-89",
    # Cross-Site Scripting
    "javascript.lang.security.audit.xss": "CWE-79",
    "xss": "CWE-79",
    "cross-site-scripting": "CWE-79",
    "xss-ssrf": "CWE-79",
    "java.xss.": "CWE-79",
    # Hardcoded Secrets
    "hardcoded-password": "CWE-798",
    "hardcoded-secret": "CWE-798",
    "hardcoded-credentials": "CWE-798",
    "generic-secrets": "CWE-798",
    "secrets": "CWE-798",
    "java.secrets.": "CWE-798",
    # Command Injection
    "command-injection": "CWE-78",
    "os-command-injection": "CWE-78",
    "subprocess-shell-true": "CWE-78",
    "dangerous-subprocess": "CWE-78",
    "tainted-cmd": "CWE-78",
    "runtime-exec": "CWE-78",
    "process-builder": "CWE-78",
    "java.lang.command-injection": "CWE-78",
    # Path Traversal
    "path-traversal": "CWE-22",
    "directory-traversal": "CWE-22",
    "path-joining": "CWE-22",
    "httpservlet-path-traversal": "CWE-22",
    "java.lang.path-traversal": "CWE-22",
    # Insecure JWT
    "insecure-jwt": "CWE-347",
    "jwt-none-algorithm": "CWE-347",
    # Insecure Deserialization
    "insecure-deserialization": "CWE-502",
    "deserialization": "CWE-502",
    "java.lang.insecure-deserialization": "CWE-502",
    # XML External Entity (XXE)
    "xxe": "CWE-611",
    "xml-external-entity": "CWE-611",
    "java.xml.xxe": "CWE-611",
    # Cryptographic issues
    "weak-cipher": "CWE-327",
    "weak-hash": "CWE-328",
    "insecure-random": "CWE-330",
    "crypto": "CWE-327",
    "hash": "CWE-328",
    "java.crypto.": "CWE-327",
    # Insecure TLS / SSL
    "trust-manager": "CWE-295",
    "insecure-trust-manager": "CWE-295",
    "hostname-verifier": "CWE-295",
    "java.ssl.": "CWE-295",
}

# Vulnerability type mapping from Semgrep patterns
VULNERABILITY_TYPE_MAPPING: Dict[str, VulnerabilityType] = {
    "sql-injection": VulnerabilityType.SQL_INJECTION,
    "sql_injection": VulnerabilityType.SQL_INJECTION,
    "dangerous-sql": VulnerabilityType.SQL_INJECTION,
    "tainted-sql": VulnerabilityType.SQL_INJECTION,
    "sqli": VulnerabilityType.SQL_INJECTION,
    "java.sql.": VulnerabilityType.SQL_INJECTION,
    "xss": VulnerabilityType.CROSS_SITE_SCRIPTING,
    "cross-site-scripting": VulnerabilityType.CROSS_SITE_SCRIPTING,
    "java.xss.": VulnerabilityType.CROSS_SITE_SCRIPTING,
    "hardcoded-password": VulnerabilityType.HARDCODED_SECRET,
    "hardcoded-secret": VulnerabilityType.HARDCODED_SECRET,
    "hardcoded-credentials": VulnerabilityType.HARDCODED_SECRET,
    "generic-secrets": VulnerabilityType.HARDCODED_SECRET,
    "java.secrets.": VulnerabilityType.HARDCODED_SECRET,
    "command-injection": VulnerabilityType.COMMAND_INJECTION,
    "os-command-injection": VulnerabilityType.COMMAND_INJECTION,
    "subprocess-shell": VulnerabilityType.COMMAND_INJECTION,
    "dangerous-subprocess": VulnerabilityType.COMMAND_INJECTION,
    "tainted-cmd": VulnerabilityType.COMMAND_INJECTION,
    "runtime-exec": VulnerabilityType.COMMAND_INJECTION,
    "process-builder": VulnerabilityType.COMMAND_INJECTION,
    "java.lang.command-injection": VulnerabilityType.COMMAND_INJECTION,
    "path-traversal": VulnerabilityType.PATH_TRAVERSAL,
    "directory-traversal": VulnerabilityType.PATH_TRAVERSAL,
    "path-joining": VulnerabilityType.PATH_TRAVERSAL,
    "httpservlet-path-traversal": VulnerabilityType.PATH_TRAVERSAL,
    "java.lang.path-traversal": VulnerabilityType.PATH_TRAVERSAL,
    "insecure-jwt": VulnerabilityType.INSECURE_JWT,
    "jwt-none-algorithm": VulnerabilityType.INSECURE_JWT,
    "insecure-deserialization": VulnerabilityType.INSECURE_DESERIALIZATION,
    "deserialization": VulnerabilityType.INSECURE_DESERIALIZATION,
    "java.lang.insecure-deserialization": VulnerabilityType.INSECURE_DESERIALIZATION,
    "xxe": VulnerabilityType.SECURITY_MISCONFIGURATION,
    "xml-external-entity": VulnerabilityType.SECURITY_MISCONFIGURATION,
    "java.xml.xxe": VulnerabilityType.SECURITY_MISCONFIGURATION,
    "weak-cipher": VulnerabilityType.SECURITY_MISCONFIGURATION,
    "weak-hash": VulnerabilityType.SECURITY_MISCONFIGURATION,
    "insecure-random": VulnerabilityType.SECURITY_MISCONFIGURATION,
    "trust-manager": VulnerabilityType.SECURITY_MISCONFIGURATION,
    "hostname-verifier": VulnerabilityType.SECURITY_MISCONFIGURATION,
    "java.crypto.": VulnerabilityType.SECURITY_MISCONFIGURATION,
    "java.ssl.": VulnerabilityType.SECURITY_MISCONFIGURATION,
}


class SemgrepRunner:
    """
    Safe execution and result parsing for Semgrep security scans.

    Runs Semgrep in a subprocess with timeout and output capture.
    When Semgrep is unavailable, executes high-fidelity deterministic
    fallback pattern scanner.
    """

    # Default Semgrep rules to run (OWASP Top 10 + Java rules focused)
    DEFAULT_RULES = [
        "p/default",           # Default Semgrep rules
        "p/owasp-top-ten",     # OWASP Top 10
        "p/security-audit",    # Security audit rules
        "p/secrets",           # Secrets detection
        "p/java",              # Java specific security rules
    ]

    # File extensions to scan
    SCAN_EXTENSIONS = {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
        ".cs", ".c", ".cpp", ".h", ".hpp", ".rs", ".swift", ".kt",
    }

    def __init__(self, semgrep_path: Optional[str] = None):
        self.semgrep_path = semgrep_path or self._find_semgrep()
        self._is_available: Optional[bool] = None
        self._availability_error: Optional[str] = None
        self._availability_status = "FAILED"
        self.version: Optional[str] = None

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
        return "semgrep"

    def _validate_semgrep(self):
        """Validate that semgrep is available and working."""
        try:
            result = subprocess.run(
                [self.semgrep_path, "--version"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            if result.returncode == 0:
                self._is_available = True
                self.version = result.stdout.strip()
                logger.info(f"[SemgrepRunner] Semgrep version: {result.stdout.strip()}")
            else:
                self._is_available = False
                self._availability_status = "FAILED"
                self._availability_error = result.stderr[:500] or "Semgrep version check failed"
                logger.warning(f"[SemgrepRunner] Semgrep validation warning: {result.stderr}")
        except FileNotFoundError:
            self._is_available = False
            self._availability_status = "FAILED"
            self._availability_error = "Semgrep executable is unavailable"
            logger.error("[SemgrepRunner] Semgrep executable is unavailable.")
        except subprocess.TimeoutExpired:
            self._is_available = False
            self._availability_status = "TIMEOUT"
            self._availability_error = "Semgrep version check timed out"
            logger.warning("[SemgrepRunner] Semgrep version check timed out.")
        except Exception as e:
            self._is_available = False
            self._availability_status = "FAILED"
            self._availability_error = str(e)[:500]
            logger.warning(f"[SemgrepRunner] Semgrep validation error: {e}")

    def _is_semgrep_available(self) -> bool:
        """Check if Semgrep is available and working, with caching."""
        if self._is_available is not None:
            return self._is_available
        self._validate_semgrep()
        return bool(self._is_available)

    def _select_rules_for_target(self, target_path: str) -> List[str]:
        """Select appropriate Semgrep rulesets based on target files."""
        # Detect if target is purely Java to optimize rule execution time
        is_java_only = False
        if os.path.isfile(target_path) and target_path.endswith(".java"):
            is_java_only = True
        elif os.path.isdir(target_path):
            all_files = []
            for root, _, files in os.walk(target_path):
                for f in files:
                    ext = os.path.splitext(f)[1].lower()
                    if ext in self.SCAN_EXTENSIONS:
                        all_files.append(ext)
            if all_files and all(ext == ".java" for ext in all_files):
                is_java_only = True

        if is_java_only:
            return ["p/owasp-top-ten", "p/java"]
        return self.DEFAULT_RULES

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

        # Validate target path
        if not os.path.exists(target_path):
            raise ValueError(f"Target path does not exist: {target_path}")

        # Check if Semgrep is available
        if not self._is_semgrep_available():
            logger.error("[SemgrepRunner] Required Semgrep scanner is unavailable")
            return [], {
                "error": self._availability_error or "Semgrep executable is unavailable",
                "scan_duration_ms": int((time.time() - scan_start) * 1000),
                "status": self._availability_status,
                "scanner": "semgrep",
            }

        effective_rules = rules or self._select_rules_for_target(target_path)

        # Build Semgrep command
        cmd = [
            self.semgrep_path,
            "--json",
            "--quiet",
            "--timeout", str(timeout_seconds),
        ]

        # Add rules
        for rule in effective_rules:
            cmd.extend(["--config", rule])

        # Add target
        cmd.append(target_path)

        logger.info(f"[SemgrepRunner] Running scan: {' '.join(cmd)}")

        try:
            cwd_path = target_path if os.path.isdir(target_path) else os.path.dirname(target_path)
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 10,
                cwd=cwd_path or None,
            )

            scan_duration_ms = int((time.time() - scan_start) * 1000)

            if result.returncode != 0:
                raw_error = result.stderr or result.stdout
                error = raw_error[:500] if raw_error else f"Semgrep exited with status {result.returncode}"
                failure_status = "TIMEOUT" if re.search(r"\b(?:timed? out|timeout)\b", error, re.IGNORECASE) else "FAILED"
                logger.error(f"[SemgrepRunner] Scan failed: {error}")
                return [], {
                    "error": error,
                    "exit_code": result.returncode,
                    "scan_duration_ms": scan_duration_ms,
                    "status": failure_status,
                    "scanner": "semgrep",
                }

            # Parse results
            try:
                findings = self._parse_results(result.stdout, result.stderr)
            except ValueError as e:
                error = str(e)[:500]
                failure_status = "TIMEOUT" if re.search(r"\b(?:timed? out|timeout)\b", error, re.IGNORECASE) else "FAILED"
                return [], {
                    "error": error,
                    "exit_code": result.returncode,
                    "scan_duration_ms": scan_duration_ms,
                    "status": failure_status,
                    "scanner": "semgrep",
                }

            try:
                target_root = os.path.abspath(target_path)
                if not os.path.isdir(target_root):
                    target_root = os.path.dirname(target_root)
                for finding in findings:
                    finding_path = finding.file
                    absolute_finding = (
                        os.path.abspath(finding_path)
                        if os.path.isabs(finding_path)
                        else os.path.abspath(os.path.join(target_root, finding_path))
                    )
                    relative_finding = os.path.relpath(absolute_finding, target_root)
                    if relative_finding == os.pardir or relative_finding.startswith(os.pardir + os.sep):
                        raise ValueError("Semgrep returned a finding outside the scan target")
                    finding.file = relative_finding.replace(os.sep, "/")
            except (OSError, ValueError) as e:
                return [], {
                    "error": f"Invalid Semgrep finding path: {e}",
                    "scan_duration_ms": int((time.time() - scan_start) * 1000),
                    "status": "FAILED",
                    "scanner": "semgrep",
                }

            metadata = {
                "scan_command": " ".join(cmd),
                "scan_duration_ms": scan_duration_ms,
                "exit_code": result.returncode,
                "rules_used": effective_rules,
                "target_path": target_path,
                "stderr": result.stderr[:500] if result.stderr else None,
                "scanner": "semgrep",
                "scanner_version": self.version,
                "status": "COMPLETED",
            }

            logger.info(f"[SemgrepRunner] Scan completed in {scan_duration_ms}ms with {len(findings)} findings")
            return findings, metadata

        except subprocess.TimeoutExpired:
            logger.error(f"[SemgrepRunner] Scan timed out after {timeout_seconds}s")
            return [], {
                "error": "Scan timed out",
                "timeout_seconds": timeout_seconds,
                "status": "TIMEOUT",
                "scanner": "semgrep",
            }
        except FileNotFoundError:
            logger.error("[SemgrepRunner] Semgrep executable disappeared before scan")
            self._is_available = False
            return [], {
                "error": "Semgrep executable is unavailable",
                "scan_duration_ms": int((time.time() - scan_start) * 1000),
                "status": "FAILED",
                "scanner": "semgrep",
            }
        except Exception as e:
            logger.error(f"[SemgrepRunner] Scan failed: {e}", exc_info=True)
            return [], {
                "error": str(e),
                "status": "FAILED",
                "scanner": "semgrep",
            }

    def _fallback_scan(
        self, target_path: str, scan_start: float
    ) -> Tuple[List[SemgrepScanResult], Dict[str, Any]]:
        """
        Fallback pattern-based scanner when Semgrep is not available.

        Uses deterministic patterns for Python, JS/TS, and Java vulnerabilities.
        """
        findings: List[SemgrepScanResult] = []

        # Common multi-language patterns
        generic_patterns = [
            # SQL Injection (Python, JS)
            (r'execute\s*\(\s*["\'].*\+', "sql-injection", "ERROR", "SQL injection via string concatenation"),
            (r'query\s*\(\s*["\'].*\+', "sql-injection", "ERROR", "SQL injection via string concatenation"),
            (r'\.format\s*\(.*(?:SELECT|INSERT|UPDATE|DELETE)', "sql-injection", "WARNING", "Potential SQL injection via string formatting"),
            # XSS (JS)
            (r'innerHTML\s*=', "xss", "ERROR", "XSS via innerHTML assignment"),
            (r'document\.write\s*\(', "xss", "WARNING", "Potential XSS via document.write"),
            # Hardcoded Secrets (Python, JS)
            (r'(?:password|secret|api_key|apikey)\s*=\s*["\'][^"\']+["\']', "hardcoded-password", "WARNING", "Hardcoded secret detected"),
            (r'(?:PASSWORD|SECRET|API_KEY|APIKEY)\s*=\s*["\'][^"\']+["\']', "hardcoded-password", "ERROR", "Hardcoded secret detected"),
            # Command Injection (Python)
            (r'os\.system\s*\(', "command-injection", "ERROR", "Command injection via os.system"),
            (r'subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True', "command-injection", "ERROR", "Command injection via subprocess with shell=True"),
            # Path Traversal (Python)
            (r'open\s*\(.*\+', "path-traversal", "WARNING", "Potential path traversal via string concatenation"),
            # Insecure JWT
            (r'algorithm.*none', "insecure-jwt", "ERROR", "Insecure JWT with none algorithm"),
        ]

        # Java-specific deterministic vulnerability patterns
        java_patterns = [
            # SQL Injection (Statement execute, executeQuery, executeUpdate, string concat in SQL)
            (
                r'(?:\.execute|\.executeQuery|\.executeUpdate)\s*\(\s*(?:["\'].*\+|[a-zA-Z0-9_]+\s*\+)',
                "java.sql.sqli-string-concat",
                "ERROR",
                "SQL injection via unsanitized string concatenation in SQL execution"
            ),
            (
                r'prepareStatement\s*\(\s*(?:["\'].*\+|[a-zA-Z0-9_]+\s*\+)',
                "java.sql.prepared-statement-sqli",
                "ERROR",
                "SQL injection via dynamic query string concatenation in prepareStatement"
            ),
            (
                r'(?:SELECT|INSERT|UPDATE|DELETE)\s+.*["\']\s*\+\s*[a-zA-Z0-9_]+',
                "java.sql.concatenated-sql-command",
                "WARNING",
                "Potential SQL injection via concatenated SQL command"
            ),
            # Command Injection (Runtime.getRuntime().exec, ProcessBuilder)
            (
                r'Runtime\.getRuntime\(\)\.exec\s*\(',
                "java.lang.command-injection-runtime-exec",
                "ERROR",
                "Command injection via Runtime.getRuntime().exec"
            ),
            (
                r'new\s+ProcessBuilder\s*\(',
                "java.lang.command-injection-process-builder",
                "ERROR",
                "Potential command injection via ProcessBuilder invocation"
            ),
            # Path Traversal (File, FileInputStream, FileOutputStream, Paths.get with concat or user input)
            (
                r'new\s+File\s*\([^,)]*,\s*(?:request\.getParameter|req\.getParameter|[a-zA-Z0-9_]*param[a-zA-Z0-9_]*|\.\.)',
                "java.lang.path-traversal-file",
                "ERROR",
                "Potential path traversal via untrusted input in File constructor"
            ),
            (
                r'new\s+FileInputStream\s*\([^)]*(?:request\.getParameter|req\.getParameter|[a-zA-Z0-9_]*param|\.\.)',
                "java.lang.path-traversal-inputstream",
                "ERROR",
                "Potential path traversal via FileInputStream"
            ),
            (
                r'new\s+FileOutputStream\s*\([^)]*(?:request\.getParameter|req\.getParameter|[a-zA-Z0-9_]*param|\.\.)',
                "java.lang.path-traversal-outputstream",
                "ERROR",
                "Potential path traversal via FileOutputStream"
            ),
            (
                r'Paths\.get\s*\([^)]*(?:request\.getParameter|req\.getParameter|\.\.)',
                "java.lang.path-traversal-paths-get",
                "ERROR",
                "Potential path traversal via Paths.get with user input"
            ),
            # Insecure Deserialization
            (
                r'(?:\.readObject|\.readUnshared)\s*\(',
                "java.lang.insecure-deserialization",
                "ERROR",
                "Insecure deserialization via ObjectInputStream.readObject"
            ),
            (
                r'new\s+XMLDecoder\s*\(',
                "java.lang.insecure-deserialization-xmldecoder",
                "ERROR",
                "Insecure deserialization via XMLDecoder"
            ),
            # XML External Entity (XXE)
            (
                r'(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\(',
                "java.xml.xxe-unrestricted-entity-expansion",
                "WARNING",
                "Potential XML External Entity (XXE) vulnerability in parser configuration"
            ),
            # Weak Cryptography
            (
                r'Cipher\.getInstance\s*\(\s*["\'](?:DES|DESede|RC2|RC4|Blowfish|AES/ECB)',
                "java.crypto.weak-cipher",
                "ERROR",
                "Use of broken or weak cryptographic cipher algorithm"
            ),
            (
                r'MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-1|MD2|MD4)',
                "java.crypto.weak-hash",
                "WARNING",
                "Use of weak cryptographic hash algorithm (MD5 or SHA-1)"
            ),
            (
                r'new\s+java\.util\.Random\s*\(',
                "java.crypto.insecure-random",
                "LOW",
                "Use of cryptographically weak pseudo-random generator"
            ),
            # Hardcoded Secrets
            (
                r'(?:String|char\[\])\s+(?:password|secretKey|apiKey|passwd|token)\s*=\s*["\'][^"\']{4,}["\']',
                "java.secrets.hardcoded-credential",
                "WARNING",
                "Hardcoded credential or secret key detected in source"
            ),
            # Cross-Site Scripting (XSS)
            (
                r'response\.getWriter\(\)\.(?:print|write|println)\s*\(.*(?:request\.getParameter|req\.getParameter)',
                "java.xss.response-writer-unencoded",
                "ERROR",
                "Reflected cross-site scripting via unencoded HttpServletResponse output"
            ),
            # Insecure TLS / SSL
            (
                r'ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier',
                "java.ssl.insecure-hostname-verifier",
                "ERROR",
                "Insecure HostnameVerifier disables SSL/TLS hostname verification"
            ),
        ]

        # Scan single file or walk directory
        targets = []
        if os.path.isfile(target_path):
            targets.append(target_path)
        else:
            for root, dirs, files in os.walk(target_path):
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'venv', '.git']]
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext in self.SCAN_EXTENSIONS:
                        targets.append(os.path.join(root, file))

        for file_path in targets:
            rel_path = os.path.relpath(file_path, target_path) if os.path.isdir(target_path) else os.path.basename(file_path)
            is_java = file_path.endswith(".java")
            active_patterns = java_patterns if is_java else generic_patterns

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                lines = content.splitlines()
                for line_num, line in enumerate(lines, 1):
                    for pattern, rule_id, severity, message in active_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            cwe_id = None
                            for k, v in CWE_MAPPING.items():
                                if k in rule_id.lower():
                                    cwe_id = v
                                    break

                            findings.append(SemgrepScanResult(
                                rule_id=rule_id,
                                message=message,
                                severity=severity,
                                file=rel_path,
                                line=line_num,
                                metadata={
                                    "fallback_scanner": True,
                                    "cwe": [cwe_id] if cwe_id else [],
                                },
                                extra={"line_content": line.strip()[:120]},
                            ))
            except Exception as e:
                logger.warning(f"[SemgrepRunner] Failed to read file {file_path}: {e}")
                continue

        scan_duration_ms = int((time.time() - scan_start) * 1000)

        metadata = {
            "scan_command": "fallback_pattern_scanner",
            "scan_duration_ms": scan_duration_ms,
            "exit_code": 0,
            "rules_used": ["fallback-deterministic-patterns"],
            "target_path": target_path,
            "scanner": "fallback",
            "status": "COMPLETED",
            "note": "Semgrep not available, using deterministic pattern-based fallback scanner",
        }

        logger.info(f"[SemgrepRunner] Fallback scan completed in {scan_duration_ms}ms with {len(findings)} findings")
        return findings, metadata

    def _parse_results(self, stdout: str, stderr: str) -> List[SemgrepScanResult]:
        """Parse Semgrep JSON output into normalized format."""
        findings: List[SemgrepScanResult] = []

        if not stdout or not stdout.strip():
            raise ValueError("Semgrep returned empty output; scan result is unverified")

        try:
            # Robust JSON extraction
            start_idx = stdout.find('{')
            end_idx = stdout.rfind('}')
            if start_idx != -1 and end_idx != -1 and end_idx >= start_idx:
                json_str = stdout[start_idx:end_idx + 1]
                data = json.loads(json_str)
            else:
                data = json.loads(stdout)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse Semgrep JSON output: {e}") from e

        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise ValueError("Semgrep JSON output is missing the results array")

        errors = data.get("errors", [])
        if errors:
            messages = [str(error.get("message", error)) for error in errors[:5]]
            raise ValueError("Semgrep reported scan errors: " + "; ".join(messages))

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
        extra = result.get("extra", {})
        message = extra.get("message", result.get("message", "No message"))
        severity_str = extra.get("severity", result.get("severity", "WARNING"))
        file_path = result.get("path", result.get("file", "unknown"))
        line = result.get("start", {}).get("line", result.get("line", 0))
        end_line = result.get("end", {}).get("line")

        # Extract metadata
        metadata = extra.get("metadata", result.get("metadata", {}))

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
