"""
Dependency Analysis Agent for HalluciShield AI.

Analyzes dependency files to detect:
- Missing dependencies
- Suspicious dependencies
- Inconsistent versions
- Unused dependencies (deterministically identifiable)
- Potentially hallucinated packages
- Dependency-related security risks

Uses deterministic verification separate from LLM reasoning.
LLM may later be used for contextual analysis.
"""

import logging
import os
import time
import uuid
from typing import Dict, List, Optional, Set, Tuple

from app.agents.models import (
    DependencyAnalysisRequest,
    DependencyAnalysisResponse,
    DependencyFinding,
    DependencyFindingType,
    DependencyInfo,
    DependencySeverity,
    DependencyType,
    VerificationEvidence,
)
from app.agents.dep_parser import DependencyFileParser
from app.agents.verification_engine import DeterministicVerificationEngine

logger = logging.getLogger(__name__)


class DependencyAnalysisAgent:
    """
    Dependency Analysis Agent that analyzes dependency manifests.

    Follows the same agent pattern as other HalluciShield agents:
    - Class-based with a single public method
    - Pydantic models for data contracts
    - Evidence-grounded findings
    - Timing instrumentation
    - Logging with [DependencyAgent] prefix
    """

    # Known suspicious package patterns
    SUSPICIOUS_PATTERNS = [
        "phantom", "fake", "auto-auth", "auto-verify", "magic",
        "crack", "keygen", "patch", "exploit", "hack", "bypass"
    ]

    # Known deprecated packages (simplified list)
    DEPRECATED_PACKAGES = {
        "npm": {"request", "left-pad", "node-uuid", "nomnom"},
        "pypi": {"optparse", "imp"},
        "maven": {"javax.xml.bind:jaxb-api"},
    }

    # Known security risk packages (simplified list)
    SECURITY_RISK_PACKAGES = {
        "npm": {"event-stream", "flatmap-stream", "mailparser"},
        "pypi": {"python-dateutil"},
        "maven": {},
    }

    def __init__(self):
        self.parser = DependencyFileParser()

    def analyze_dependencies(
        self,
        repository_id: str,
        workspace_path: str,
    ) -> DependencyAnalysisResponse:
        """
        Main dependency analysis pipeline.

        Args:
            repository_id: Unique identifier for the repository
            workspace_path: Path to the repository workspace

        Returns:
            DependencyAnalysisResponse with normalized findings
        """
        logger.info(f"[DependencyAgent] Starting dependency analysis for repository: {repository_id}")
        start_time = time.time()

        try:
            # Stage 1: Parse all dependency files
            dependencies = self.parser.parse_workspace(workspace_path)
            logger.info(f"[DependencyAgent] Found {len(dependencies)} dependencies across manifest files")

            # Stage 2: Extract imports from source code for unused detection
            source_imports = self._extract_all_imports(workspace_path)
            logger.info(f"[DependencyAgent] Found {len(source_imports)} unique imports in source code")

            # Stage 3: Analyze dependencies
            findings = self._analyze_dependencies(
                dependencies=dependencies,
                source_imports=source_imports,
                repository_id=repository_id,
            )
            logger.info(f"[DependencyAgent] Generated {len(findings)} findings")

            # Stage 4: Compile response
            response = self._compile_response(
                repository_id=repository_id,
                findings=findings,
                dependencies=dependencies,
                start_time=start_time,
            )

            logger.info(
                f"[DependencyAgent] Analysis complete for {repository_id}: "
                f"{response.total_findings} findings "
                f"(Critical: {response.critical_count}, High: {response.high_count}, "
                f"Medium: {response.medium_count}, Low: {response.low_count})"
            )

            return response

        except Exception as e:
            logger.error(
                f"[DependencyAgent] Analysis failed for {repository_id}: {e}",
                exc_info=True,
            )
            duration_ms = int((time.time() - start_time) * 1000)
            return DependencyAnalysisResponse(
                repository_id=repository_id,
                total_findings=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                findings=[],
                analysis_duration_ms=duration_ms,
            )

    def _extract_all_imports(self, workspace_path: str) -> Set[str]:
        """Extract all imports from source files in workspace."""
        all_imports: Set[str] = set()

        if not os.path.exists(workspace_path):
            return all_imports

        source_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".java"}

        for root, dirs, files in os.walk(workspace_path):
            # Skip non-source directories
            dirs[:] = [
                d for d in dirs
                if not d.startswith('.')
                and d not in ['node_modules', '__pycache__', 'venv', '.venv', 'env', 'dist', 'build']
            ]

            for file_name in files:
                ext = os.path.splitext(file_name)[1].lower()
                if ext in source_extensions:
                    file_path = os.path.join(root, file_name)
                    imports = self.parser.extract_imports_from_source(file_path)
                    all_imports.update(imports)

        return all_imports

    def _analyze_dependencies(
        self,
        dependencies: List[DependencyInfo],
        source_imports: Set[str],
        repository_id: str,
    ) -> List[DependencyFinding]:
        """Analyze dependencies and generate findings."""
        findings: List[DependencyFinding] = []

        # Group dependencies by ecosystem
        npm_deps = [d for d in dependencies if d.ecosystem == DependencyType.NPM]
        pypi_deps = [d for d in dependencies if d.ecosystem == DependencyType.PYPI]
        maven_deps = [d for d in dependencies if d.ecosystem == DependencyType.MAVEN]

        # 1. Check for hallucinated/suspicious packages
        findings.extend(self._check_suspicious_packages(dependencies, repository_id))

        # 2. Check for version inconsistencies
        findings.extend(self._check_version_inconsistencies(dependencies, repository_id))

        # 3. Check for unused dependencies (npm only for now)
        findings.extend(self._check_unused_dependencies(npm_deps, source_imports, repository_id))

        # 4. Check for deprecated packages
        findings.extend(self._check_deprecated_packages(dependencies, repository_id))

        # 5. Check for security risk packages
        findings.extend(self._check_security_risk_packages(dependencies, repository_id))

        return findings

    def _check_suspicious_packages(
        self,
        dependencies: List[DependencyInfo],
        repository_id: str,
    ) -> List[DependencyFinding]:
        """Check for suspicious or hallucinated packages."""
        findings: List[DependencyFinding] = []

        for dep in dependencies:
            pkg_lower = dep.name.lower()
            is_suspicious = False
            reason = ""

            # Check against known fake packages
            evidence = DeterministicVerificationEngine.verify_package(
                dep.name, dep.ecosystem.value
            )

            if evidence.registry_status == "404_NOT_FOUND":
                findings.append(DependencyFinding(
                    finding_id=f"dep-{uuid.uuid4().hex[:8]}",
                    type=DependencyFindingType.HALLUCINATED_PACKAGE,
                    severity=DependencySeverity.CRITICAL,
                    package_name=dep.name,
                    ecosystem=dep.ecosystem,
                    file=dep.file_path,
                    line=dep.line_number,
                    evidence=evidence.facts[0] if evidence.facts else "Package not found in registry",
                    description=f"Package '{dep.name}' does not exist in {dep.ecosystem.value} registry. High risk of hallucinated dependency.",
                    cwe="CWE-1395",
                    confidence=0.98,
                    fix_recommendation=f"Remove '{dep.name}' and verify the correct package name.",
                    metadata={"registry_status": evidence.registry_status},
                ))
                continue

            # Check suspicious patterns
            for pattern in self.SUSPICIOUS_PATTERNS:
                if pattern in pkg_lower:
                    is_suspicious = True
                    reason = f"Package name contains suspicious pattern: '{pattern}'"
                    break

            if is_suspicious:
                findings.append(DependencyFinding(
                    finding_id=f"dep-{uuid.uuid4().hex[:8]}",
                    type=DependencyFindingType.SUSPICIOUS_DEPENDENCY,
                    severity=DependencySeverity.HIGH,
                    package_name=dep.name,
                    ecosystem=dep.ecosystem,
                    file=dep.file_path,
                    line=dep.line_number,
                    evidence=reason,
                    description=f"Suspicious package '{dep.name}': {reason}",
                    cwe="CWE-1395",
                    confidence=0.85,
                    fix_recommendation=f"Review '{dep.name}' and ensure it is a legitimate package.",
                ))

        return findings

    def _check_version_inconsistencies(
        self,
        dependencies: List[DependencyInfo],
        repository_id: str,
    ) -> List[DependencyFinding]:
        """Check for version inconsistencies across dependency files."""
        findings: List[DependencyFinding] = []

        # Group by package name across files
        pkg_versions: Dict[str, List[DependencyInfo]] = {}
        for dep in dependencies:
            pkg_versions.setdefault(dep.name, []).append(dep)

        # Check for same package with different versions
        for pkg_name, deps in pkg_versions.items():
            versions = set(d.version for d in deps if d.version)
            if len(versions) > 1:
                files = [d.file_path for d in deps]
                findings.append(DependencyFinding(
                    finding_id=f"dep-{uuid.uuid4().hex[:8]}",
                    type=DependencyFindingType.VERSION_INCONSISTENCY,
                    severity=DependencySeverity.MEDIUM,
                    package_name=pkg_name,
                    ecosystem=deps[0].ecosystem,
                    file=files[0],
                    evidence=f"Multiple versions found: {', '.join(versions)} in {', '.join(set(files))}",
                    description=f"Package '{pkg_name}' has inconsistent versions across dependency files.",
                    confidence=0.9,
                    fix_recommendation="Align version specifications across all dependency files.",
                    metadata={"versions": list(versions), "files": list(set(files))},
                ))

        return findings

    def _check_unused_dependencies(
        self,
        dependencies: List[DependencyInfo],
        source_imports: Set[str],
        repository_id: str,
    ) -> List[DependencyFinding]:
        """Check for dependencies that are not imported in source code."""
        findings: List[DependencyFinding] = []

        # Only check non-dev dependencies
        prod_deps = [d for d in dependencies if not d.is_dev_dependency]

        for dep in prod_deps:
            # Normalize package name for comparison
            pkg_name = dep.name.lower()
            import_name = pkg_name.split("/")[-1] if "/" in pkg_name else pkg_name

            # Check if package is imported
            is_imported = False
            for imp in source_imports:
                imp_lower = imp.lower()
                if import_name in imp_lower or imp_lower in import_name:
                    is_imported = True
                    break

            if not is_imported and dep.ecosystem == DependencyType.NPM:
                # Only report for npm where we can reliably detect imports
                findings.append(DependencyFinding(
                    finding_id=f"dep-{uuid.uuid4().hex[:8]}",
                    type=DependencyFindingType.UNUSED_DEPENDENCY,
                    severity=DependencySeverity.LOW,
                    package_name=dep.name,
                    ecosystem=dep.ecosystem,
                    file=dep.file_path,
                    line=dep.line_number,
                    evidence=f"Package '{dep.name}' is listed as a dependency but not imported in source code.",
                    description=f"Potentially unused dependency: '{dep.name}'",
                    confidence=0.7,
                    fix_recommendation=f"Verify if '{dep.name}' is needed. Remove if unused to reduce bundle size.",
                ))

        return findings

    def _check_deprecated_packages(
        self,
        dependencies: List[DependencyInfo],
        repository_id: str,
    ) -> List[DependencyFinding]:
        """Check for deprecated packages."""
        findings: List[DependencyFinding] = []

        for dep in dependencies:
            ecosystem = dep.ecosystem.value
            deprecated_list = self.DEPRECATED_PACKAGES.get(ecosystem, set())

            # For Maven, check full coordinate
            pkg_check = dep.name if dep.ecosystem == DependencyType.MAVEN else dep.name.lower()

            if pkg_check in deprecated_list:
                findings.append(DependencyFinding(
                    finding_id=f"dep-{uuid.uuid4().hex[:8]}",
                    type=DependencyFindingType.DEPRECATED_PACKAGE,
                    severity=DependencySeverity.MEDIUM,
                    package_name=dep.name,
                    ecosystem=dep.ecosystem,
                    file=dep.file_path,
                    line=dep.line_number,
                    evidence=f"Package '{dep.name}' is deprecated.",
                    description=f"Deprecated package '{dep.name}' should be replaced with a modern alternative.",
                    cwe="CWE-1104",
                    confidence=0.95,
                    fix_recommendation=f"Replace '{dep.name}' with its recommended successor.",
                ))

        return findings

    def _check_security_risk_packages(
        self,
        dependencies: List[DependencyInfo],
        repository_id: str,
    ) -> List[DependencyFinding]:
        """Check for packages with known security risks."""
        findings: List[DependencyFinding] = []

        for dep in dependencies:
            ecosystem = dep.ecosystem.value
            risk_list = self.SECURITY_RISK_PACKAGES.get(ecosystem, set())

            if dep.name.lower() in risk_list:
                findings.append(DependencyFinding(
                    finding_id=f"dep-{uuid.uuid4().hex[:8]}",
                    type=DependencyFindingType.SECURITY_RISK,
                    severity=DependencySeverity.HIGH,
                    package_name=dep.name,
                    ecosystem=dep.ecosystem,
                    file=dep.file_path,
                    line=dep.line_number,
                    evidence=f"Package '{dep.name}' has known security risks.",
                    description=f"Package '{dep.name}' has known security vulnerabilities or risks.",
                    cwe="CWE-1395",
                    confidence=0.9,
                    fix_recommendation=f"Review security advisories for '{dep.name}' and consider alternatives.",
                ))

        return findings

    def _compile_response(
        self,
        repository_id: str,
        findings: List[DependencyFinding],
        dependencies: List[DependencyInfo],
        start_time: float,
    ) -> DependencyAnalysisResponse:
        """Compile findings into DependencyAnalysisResponse."""
        critical_count = sum(1 for f in findings if f.severity == DependencySeverity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == DependencySeverity.HIGH)
        medium_count = sum(1 for f in findings if f.severity == DependencySeverity.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == DependencySeverity.LOW)

        duration_ms = int((time.time() - start_time) * 1000)

        return DependencyAnalysisResponse(
            repository_id=repository_id,
            total_findings=len(findings),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            findings=findings,
            dependencies_scanned=len(dependencies),
            analysis_duration_ms=duration_ms,
        )
