"""
Security Analysis Agent for HalluciShield AI.

Integrates Semgrep to detect security vulnerabilities in source code:
- SQL Injection
- Cross-Site Scripting (XSS)
- Hardcoded Secrets
- Command Injection
- Path Traversal
- Insecure JWT Usage

Uses a multi-stage pipeline:
1. Static extraction (reuses RepositoryAnalyzer)
2. Semgrep vulnerability scanning
3. Result normalization and CWE mapping
4. Severity assignment
5. Evidence preservation and remediation context generation

LLM is NOT used to replace Semgrep for vulnerability detection.
LLM may later be used for reasoning and contextual analysis.
"""

import logging
import time
import uuid
from typing import List, Dict, Any, Optional

from app.analyzer.engine import RepositoryAnalyzer
from app.agents.models import (
    SecurityAnalysisRequest,
    SecurityAnalysisResponse,
    SecurityFinding,
    SemgrepScanResult,
    VulnerabilitySeverity,
    VulnerabilityType,
)
from app.agents.semgrep_runner import (
    SemgrepRunner,
    CWE_MAPPING,
    VULNERABILITY_TYPE_MAPPING,
    SEMGREP_SEVERITY_MAP,
)

logger = logging.getLogger(__name__)


class SecurityAnalysisAgent:
    """
    Security Analysis Agent that integrates Semgrep for vulnerability detection.

    Follows the same agent pattern as HallucinationDetectionAgent:
    - Class-based with a single public method
    - Pydantic models for data contracts
    - Evidence-grounded findings
    - Timing instrumentation
    - Logging with [SecurityAgent] prefix
    """

    def __init__(self):
        self.analyzer = RepositoryAnalyzer()
        self.semgrep = SemgrepRunner()

    def analyze_security(
        self,
        repository_id: str,
        workspace_path: str,
        scan_rules: Optional[List[str]] = None,
    ) -> SecurityAnalysisResponse:
        """
        Main security analysis pipeline.

        Args:
            repository_id: Unique identifier for the repository
            workspace_path: Path to the repository workspace
            scan_rules: Optional list of Semgrep rules to use

        Returns:
            SecurityAnalysisResponse with normalized vulnerability findings
        """
        logger.info(f"[SecurityAgent] Starting security analysis for repository: {repository_id}")
        start_time = time.time()

        try:
            # Stage 1: Run Semgrep scan
            semgrep_findings, scan_metadata = self.semgrep.run_scan(
                target_path=workspace_path,
                rules=scan_rules,
                timeout_seconds=120,
            )
            logger.info(
                f"[SecurityAgent] Semgrep scan completed: {len(semgrep_findings)} raw findings"
            )

            # Stage 2: Normalize and enrich findings
            normalized_findings = self._normalize_findings(
                semgrep_findings, repository_id
            )
            logger.info(
                f"[SecurityAgent] Normalized findings: {len(normalized_findings)} vulnerabilities"
            )

            # Stage 3: Assign severity and compile response
            response = self._compile_response(
                repository_id=repository_id,
                findings=normalized_findings,
                scan_metadata=scan_metadata,
                start_time=start_time,
            )

            logger.info(
                f"[SecurityAgent] Analysis complete for {repository_id}: "
                f"{response.total_vulnerabilities} vulnerabilities "
                f"(Critical: {response.critical_count}, High: {response.high_count}, "
                f"Medium: {response.medium_count}, Low: {response.low_count})"
            )

            return response

        except Exception as e:
            logger.error(
                f"[SecurityAgent] Analysis failed for {repository_id}: {e}",
                exc_info=True,
            )
            # Return empty response on failure
            duration_ms = int((time.time() - start_time) * 1000)
            return SecurityAnalysisResponse(
                repository_id=repository_id,
                total_vulnerabilities=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                findings=[],
                scan_duration_ms=duration_ms,
            )

    def _normalize_findings(
        self,
        semgrep_findings: List[SemgrepScanResult],
        repository_id: str,
    ) -> List[SecurityFinding]:
        """
        Normalize Semgrep findings into SecurityFinding format.

        Maps rule IDs to CWE, assigns vulnerability types, and preserves evidence.
        """
        normalized: List[SecurityFinding] = []

        for finding in semgrep_findings:
            try:
                security_finding = self._normalize_single_finding(finding, repository_id)
                if security_finding:
                    normalized.append(security_finding)
            except Exception as e:
                logger.warning(
                    f"[SecurityAgent] Failed to normalize finding {finding.rule_id}: {e}"
                )
                continue

        return normalized

    def _normalize_single_finding(
        self,
        semgrep_finding: SemgrepScanResult,
        repository_id: str,
    ) -> Optional[SecurityFinding]:
        """Normalize a single Semgrep finding into SecurityFinding format."""
        rule_id = semgrep_finding.rule_id
        rule_lower = rule_id.lower()

        # Determine vulnerability type
        vuln_type = self._determine_vulnerability_type(rule_lower)

        # Determine severity
        severity = self._determine_severity(semgrep_finding.severity)

        # Map to CWE
        cwe = self._map_to_cwe(rule_lower)

        # Generate finding ID
        finding_id = f"sec-{uuid.uuid4().hex[:8]}"

        # Build evidence string
        evidence = self._build_evidence(semgrep_finding)

        # Generate fix recommendation
        fix_recommendation = self._generate_fix_recommendation(vuln_type, rule_lower)

        # Build metadata
        metadata = {
            "repository_id": repository_id,
            "original_rule_id": rule_id,
            "semgrep_severity": semgrep_finding.severity,
            "semgrep_metadata": semgrep_finding.metadata,
            "semgrep_extra": semgrep_finding.extra,
        }

        return SecurityFinding(
            finding_id=finding_id,
            type=vuln_type,
            severity=severity,
            cwe=cwe,
            file=semgrep_finding.file,
            line=semgrep_finding.line,
            end_line=semgrep_finding.end_line,
            evidence=evidence,
            description=semgrep_finding.message,
            scanner="semgrep",
            rule_id=rule_id,
            confidence=0.95,
            fix_recommendation=fix_recommendation,
            metadata=metadata,
        )

    def _determine_vulnerability_type(self, rule_id_lower: str) -> VulnerabilityType:
        """Determine vulnerability type from Semgrep rule ID."""
        for pattern, vuln_type in VULNERABILITY_TYPE_MAPPING.items():
            if pattern in rule_id_lower:
                return vuln_type

        # Additional heuristics
        if "sql" in rule_id_lower or "query" in rule_id_lower:
            return VulnerabilityType.SQL_INJECTION
        elif "xss" in rule_id_lower or "script" in rule_id_lower:
            return VulnerabilityType.CROSS_SITE_SCRIPTING
        elif "secret" in rule_id_lower or "password" in rule_id_lower or "credential" in rule_id_lower:
            return VulnerabilityType.HARDCODED_SECRET
        elif "command" in rule_id_lower or "exec" in rule_id_lower or "spawn" in rule_id_lower:
            return VulnerabilityType.COMMAND_INJECTION
        elif "path" in rule_id_lower or "traversal" in rule_id_lower:
            return VulnerabilityType.PATH_TRAVERSAL
        elif "jwt" in rule_id_lower or "token" in rule_id_lower:
            return VulnerabilityType.INSECURE_JWT

        return VulnerabilityType.UNKNOWN

    def _determine_severity(self, semgrep_severity: str) -> VulnerabilitySeverity:
        """Map Semgrep severity to normalized severity."""
        return SEMGREP_SEVERITY_MAP.get(
            semgrep_severity.upper(),
            VulnerabilitySeverity.MEDIUM,
        )

    def _map_to_cwe(self, rule_id_lower: str) -> Optional[str]:
        """Map Semgrep rule ID to CWE identifier."""
        for pattern, cwe in CWE_MAPPING.items():
            if pattern in rule_id_lower:
                return cwe
        return None

    def _build_evidence(self, finding: SemgrepScanResult) -> str:
        """Build evidence string from Semgrep finding."""
        parts = [
            f"Rule: {finding.rule_id}",
            f"Severity: {finding.severity}",
            f"File: {finding.file}:{finding.line}",
            f"Message: {finding.message}",
        ]

        # Add metadata if available
        if finding.metadata:
            if "owasp" in finding.metadata:
                parts.append(f"OWASP: {finding.metadata['owasp']}")
            if "cwe" in finding.metadata:
                parts.append(f"CWE: {finding.metadata['cwe']}")

        return " | ".join(parts)

    def _generate_fix_recommendation(
        self, vuln_type: VulnerabilityType, rule_id: str
    ) -> Optional[str]:
        """Generate remediation context based on vulnerability type."""
        recommendations = {
            VulnerabilityType.SQL_INJECTION: (
                "Use parameterized queries or prepared statements instead of string concatenation. "
                "Validate and sanitize all user inputs before including in SQL queries."
            ),
            VulnerabilityType.CROSS_SITE_SCRIPTING: (
                "Encode all user-supplied data before rendering in HTML. "
                "Use Content Security Policy (CSP) headers. "
                "Avoid using innerHTML or document.write with user data."
            ),
            VulnerabilityType.HARDCODED_SECRET: (
                "Move secrets to environment variables or a secrets manager. "
                "Never commit credentials to version control. "
                "Use .env files (excluded from git) for local development."
            ),
            VulnerabilityType.COMMAND_INJECTION: (
                "Avoid passing user input to system commands. "
                "If shell execution is required, use parameterized APIs and validate inputs. "
                "Consider using subprocess with shell=False."
            ),
            VulnerabilityType.PATH_TRAVERSAL: (
                "Validate and sanitize file paths. "
                "Use os.path.abspath() and verify the resolved path is within allowed directories. "
                "Avoid directly concatenating user input into file paths."
            ),
            VulnerabilityType.INSECURE_JWT: (
                "Never use 'none' algorithm for JWT signing. "
                "Use strong signing algorithms (RS256, ES256). "
                "Validate algorithm and issuer claims server-side."
            ),
        }
        return recommendations.get(vuln_type)

    def _compile_response(
        self,
        repository_id: str,
        findings: List[SecurityFinding],
        scan_metadata: Dict[str, Any],
        start_time: float,
    ) -> SecurityAnalysisResponse:
        """Compile findings into SecurityAnalysisResponse with severity counts."""
        critical_count = sum(1 for f in findings if f.severity == VulnerabilitySeverity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == VulnerabilitySeverity.HIGH)
        medium_count = sum(1 for f in findings if f.severity == VulnerabilitySeverity.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == VulnerabilitySeverity.LOW)

        duration_ms = int((time.time() - start_time) * 1000)

        return SecurityAnalysisResponse(
            repository_id=repository_id,
            total_vulnerabilities=len(findings),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            findings=findings,
            scan_duration_ms=duration_ms,
            scanner="semgrep",
        )
