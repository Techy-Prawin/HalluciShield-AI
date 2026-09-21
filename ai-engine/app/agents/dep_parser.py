"""
Dependency File Parser for HalluciShield AI.

Parses various dependency manifest files:
- package.json (npm/yarn)
- package-lock.json (npm)
- requirements.txt (pip)
- pyproject.toml (Python)
- pom.xml (Maven/Java)

Does NOT execute package installation commands.
Only reads and parses dependency files.
"""

import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set, Tuple

from app.agents.models import DependencyInfo, DependencyType

logger = logging.getLogger(__name__)


class DependencyFileParser:
    """
    Parses dependency manifest files into normalized DependencyInfo objects.

    Supports:
    - package.json: npm/yarn dependencies
    - package-lock.json: npm lock file
    - requirements.txt: pip dependencies
    - pyproject.toml: Python project dependencies
    - pom.xml: Maven dependencies
    """

    # Supported dependency files and their types
    SUPPORTED_FILES = {
        "package.json": DependencyType.NPM,
        "package-lock.json": DependencyType.NPM,
        "requirements.txt": DependencyType.PYPI,
        "pyproject.toml": DependencyType.PYPI,
        "pom.xml": DependencyType.MAVEN,
    }

    def parse_workspace(self, workspace_path: str) -> List[DependencyInfo]:
        """
        Parse all dependency files in a workspace.

        Args:
            workspace_path: Path to the repository root

        Returns:
            List of DependencyInfo objects
        """
        dependencies: List[DependencyInfo] = []

        if not os.path.exists(workspace_path):
            logger.warning(f"[DependencyParser] Workspace path does not exist: {workspace_path}")
            return dependencies

        # Walk through workspace looking for dependency files
        for root, dirs, files in os.walk(workspace_path):
            # Skip common non-source directories
            dirs[:] = [
                d for d in dirs
                if not d.startswith('.')
                and d not in ['node_modules', '__pycache__', 'venv', '.venv', 'env', 'dist', 'build']
            ]

            for file_name in files:
                if file_name in self.SUPPORTED_FILES:
                    file_path = os.path.join(root, file_name)
                    rel_path = os.path.relpath(file_path, workspace_path).replace("\\", "/")

                    try:
                        file_deps = self.parse_file(file_path, rel_path)
                        dependencies.extend(file_deps)
                    except Exception as e:
                        logger.warning(f"[DependencyParser] Failed to parse {rel_path}: {e}")

        return dependencies

    def parse_file(self, file_path: str, rel_path: str) -> List[DependencyInfo]:
        """
        Parse a single dependency file.

        Args:
            file_path: Absolute path to the file
            rel_path: Relative path from workspace root

        Returns:
            List of DependencyInfo objects
        """
        file_name = os.path.basename(file_path)

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        if file_name == "package.json":
            return self._parse_package_json(content, rel_path)
        elif file_name == "package-lock.json":
            return self._parse_package_lock_json(content, rel_path)
        elif file_name == "requirements.txt":
            return self._parse_requirements_txt(content, rel_path)
        elif file_name == "pyproject.toml":
            return self._parse_pyproject_toml(content, rel_path)
        elif file_name == "pom.xml":
            return self._parse_pom_xml(content, rel_path)

        return []

    def _parse_package_json(self, content: str, rel_path: str) -> List[DependencyInfo]:
        """Parse package.json dependencies."""
        dependencies: List[DependencyInfo] = []

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.warning(f"[DependencyParser] Invalid JSON in {rel_path}: {e}")
            return dependencies

        # Parse different dependency sections
        sections = {
            "dependencies": False,
            "devDependencies": True,
            "optionalDependencies": False,
            "peerDependencies": False,
        }

        for section, is_dev in sections.items():
            deps = data.get(section, {})
            if isinstance(deps, dict):
                for pkg_name, version in deps.items():
                    dependencies.append(DependencyInfo(
                        name=pkg_name,
                        version=str(version) if version else None,
                        ecosystem=DependencyType.NPM,
                        file_path=rel_path,
                        is_dev_dependency=is_dev,
                        is_optional=(section == "optionalDependencies"),
                        source_section=section,
                    ))

        return dependencies

    def _parse_package_lock_json(self, content: str, rel_path: str) -> List[DependencyInfo]:
        """Parse package-lock.json for locked versions."""
        dependencies: List[DependencyInfo] = []

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.warning(f"[DependencyParser] Invalid JSON in {rel_path}: {e}")
            return dependencies

        # package-lock.json has a "packages" field (v2/v3) or "dependencies" field (v1)
        packages = data.get("packages", {})
        if packages:
            for pkg_path, pkg_info in packages.items():
                if pkg_path == "":
                    continue  # Skip root package
                # Extract package name from path (e.g., "node_modules/express" -> "express")
                pkg_name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
                version = pkg_info.get("version")
                if pkg_name and version:
                    dependencies.append(DependencyInfo(
                        name=pkg_name,
                        version=version,
                        ecosystem=DependencyType.NPM,
                        file_path=rel_path,
                        source_section="lockfile",
                    ))
        else:
            # v1 format
            deps = data.get("dependencies", {})
            for pkg_name, pkg_info in deps.items():
                version = pkg_info.get("version")
                if version:
                    dependencies.append(DependencyInfo(
                        name=pkg_name,
                        version=version,
                        ecosystem=DependencyType.NPM,
                        file_path=rel_path,
                        source_section="lockfile",
                    ))

        return dependencies

    def _parse_requirements_txt(self, content: str, rel_path: str) -> List[DependencyInfo]:
        """Parse requirements.txt dependencies."""
        dependencies: List[DependencyInfo] = []

        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Parse package==version or package>=version, etc.
            match = re.match(r'^([a-zA-Z0-9_-]+)\s*([><=!~]+.*)?$', line)
            if match:
                pkg_name = match.group(1)
                version = match.group(2).strip() if match.group(2) else None
                dependencies.append(DependencyInfo(
                    name=pkg_name,
                    version=version,
                    ecosystem=DependencyType.PYPI,
                    file_path=rel_path,
                    line_number=line_num,
                    source_section="requirements",
                ))

        return dependencies

    def _parse_pyproject_toml(self, content: str, rel_path: str) -> List[DependencyInfo]:
        """Parse pyproject.toml dependencies (simplified TOML parsing)."""
        dependencies: List[DependencyInfo] = []

        # Simple regex-based TOML parsing for dependencies
        # Look for [project.dependencies] or [tool.poetry.dependencies]
        in_dependencies = False
        current_section = None

        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()

            # Check for section headers
            if stripped.startswith("["):
                if "dependencies" in stripped.lower():
                    in_dependencies = True
                    current_section = stripped
                else:
                    in_dependencies = False
                continue

            if in_dependencies and "=" in stripped:
                # Parse key = value
                parts = stripped.split("=", 1)
                if len(parts) == 2:
                    key = parts[0].strip().strip('"')
                    value = parts[1].strip().strip('"')

                    # Skip version-only entries
                    if key and not key.startswith("#"):
                        dependencies.append(DependencyInfo(
                            name=key,
                            version=value if value and value != "*" else None,
                            ecosystem=DependencyType.PYPI,
                            file_path=rel_path,
                            line_number=line_num,
                            source_section="pyproject.toml",
                        ))

        return dependencies

    def _parse_pom_xml(self, content: str, rel_path: str) -> List[DependencyInfo]:
        """Parse pom.xml Maven dependencies."""
        dependencies: List[DependencyInfo] = []

        try:
            root = ET.fromstring(content)
        except ET.ParseError as e:
            logger.warning(f"[DependencyParser] Invalid XML in {rel_path}: {e}")
            return dependencies

        # Define namespace
        ns = {"m": "http://maven.apache.org/POM/4.0.0"}

        # Find dependencies in both main and profile sections
        for dep_elem in root.findall(".//m:dependency", ns):
            group_id = dep_elem.find("m:groupId", ns)
            artifact_id = dep_elem.find("m:artifactId", ns)
            version = dep_elem.find("m:version", ns)
            scope = dep_elem.find("m:scope", ns)

            if artifact_id is not None:
                pkg_name = artifact_id.text
                group = group_id.text if group_id is not None else ""
                version_str = version.text if version is not None else None
                scope_str = scope.text if scope is not None else "compile"

                # Create Maven coordinate
                maven_coord = f"{group}:{pkg_name}" if group else pkg_name

                dependencies.append(DependencyInfo(
                    name=maven_coord,
                    version=version_str,
                    ecosystem=DependencyType.MAVEN,
                    file_path=rel_path,
                    is_dev_dependency=(scope_str in ["test", "provided"]),
                    is_optional=(scope_str == "optional"),
                    source_section="dependencies",
                ))

        return dependencies

    def get_ecosystem_for_file(self, file_name: str) -> DependencyType:
        """Get the dependency ecosystem for a file."""
        return self.SUPPORTED_FILES.get(file_name, DependencyType.UNKNOWN)

    def extract_imports_from_source(self, file_path: str) -> Set[str]:
        """
        Extract import statements from source files to detect used dependencies.

        Args:
            file_path: Path to source file

        Returns:
            Set of imported module names
        """
        imports: Set[str] = set()

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return imports

        ext = os.path.splitext(file_path)[1].lower()

        if ext in [".js", ".jsx", ".ts", ".tsx"]:
            imports = self._extract_js_imports(content)
        elif ext == ".py":
            imports = self._extract_python_imports(content)
        elif ext == ".java":
            imports = self._extract_java_imports(content)

        return imports

    def _extract_js_imports(self, content: str) -> Set[str]:
        """Extract imports from JavaScript/TypeScript files."""
        imports = set()

        # import ... from 'package'
        for match in re.finditer(r"import\s+.*?\s+from\s+['\"]([^'\"]+)['\"]", content):
            module = match.group(1)
            if not module.startswith("."):
                # Extract base package name (handle scoped packages)
                if module.startswith("@"):
                    parts = module.split("/")
                    if len(parts) >= 2:
                        imports.add(f"{parts[0]}/{parts[1]}")
                else:
                    imports.add(module.split("/")[0])

        # require('package')
        for match in re.finditer(r"require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", content):
            module = match.group(1)
            if not module.startswith("."):
                if module.startswith("@"):
                    parts = module.split("/")
                    if len(parts) >= 2:
                        imports.add(f"{parts[0]}/{parts[1]}")
                else:
                    imports.add(module.split("/")[0])

        return imports

    def _extract_python_imports(self, content: str) -> Set[str]:
        """Extract imports from Python files."""
        imports = set()

        # import package
        for match in re.finditer(r"^import\s+([a-zA-Z_][a-zA-Z0-9_]*)", content, re.MULTILINE):
            imports.add(match.group(1))

        # from package import ...
        for match in re.finditer(r"^from\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+import", content, re.MULTILINE):
            imports.add(match.group(1))

        return imports

    def _extract_java_imports(self, content: str) -> Set[str]:
        """Extract imports from Java files."""
        imports = set()

        # import com.example.package
        for match in re.finditer(r"^import\s+([a-zA-Z][a-zA-Z0-9_.]*)\s*;", content, re.MULTILINE):
            full_import = match.group(1)
            # Extract package name (first 3-4 parts typically)
            parts = full_import.split(".")
            if len(parts) >= 3:
                imports.add(":".join(parts[:3]))

        return imports
