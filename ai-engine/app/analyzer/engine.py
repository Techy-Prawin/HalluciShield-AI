import os
import logging
import time
from typing import List, Dict, Set
from app.analyzer.models import (
    AnalysisResult,
    FileInfo,
    ImportItem,
    PackageReference,
    FunctionSymbol,
    ClassSymbol,
    ApiCall,
    HttpEndpoint,
    SecurityConstruct,
)
from app.analyzer.base_parser import BaseLanguageParser
from app.analyzer.python_parser import PythonParser
from app.analyzer.javascript_parser import JavaScriptParser
from app.analyzer.typescript_parser import TypeScriptParser
from app.analyzer.java_parser import JavaParser
from app.analyzer.dependency_parser import DependencyParser

logger = logging.getLogger(__name__)


class RepositoryAnalyzer:
    IGNORE_DIRS = {
        ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
        ".idea", ".vscode", "dist", "build", "target", "coverage", ".next"
    }

    BINARY_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".pdf", ".zip",
        ".tar", ".gz", ".7z", ".exe", ".dll", ".so", ".dylib", ".pyc",
        ".class", ".o", ".obj", ".bin", ".ttf", ".woff", ".woff2"
    }

    def __init__(self):
        self.parsers: List[BaseLanguageParser] = [
            PythonParser(),
            JavaScriptParser(),
            TypeScriptParser(),
            JavaParser(),
        ]

    def analyze_repository(self, repository_id: str, workspace_path: str) -> AnalysisResult:
        logger.info(f"[Analyzer] Starting static repository analysis for ID: {repository_id} at {workspace_path}")
        start_time = time.time()

        if not os.path.exists(workspace_path) or not os.path.isdir(workspace_path):
            raise ValueError(f"Workspace path does not exist or is not a directory: {workspace_path}")

        files_info: List[FileInfo] = []
        imports_list: List[ImportItem] = []
        packages_list: List[PackageReference] = []
        functions_list: List[FunctionSymbol] = []
        classes_list: List[ClassSymbol] = []
        apis_list: List[ApiCall] = []
        endpoints_list: List[HttpEndpoint] = []
        security_list: List[SecurityConstruct] = []
        errors_list: List[Dict[str, str]] = []
        detected_languages: Set[str] = set()

        for root, dirs, files in os.walk(workspace_path):
            # Exclude ignored directories
            dirs[:] = [d for d in dirs if d.lower() not in self.IGNORE_DIRS]

            for file_name in files:
                ext = os.path.splitext(file_name)[1].lower()
                if ext in self.BINARY_EXTENSIONS:
                    continue

                abs_file_path = os.path.join(root, file_name)
                rel_file_path = os.path.relpath(abs_file_path, workspace_path).replace("\\", "/")

                is_dep, is_cfg = DependencyParser.is_dependency_or_config(file_name)

                # Read content safely
                try:
                    with open(abs_file_path, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()

                    size_bytes = os.path.getsize(abs_file_path)
                    line_count = len(content.splitlines())
                except Exception as read_err:
                    logger.warning(f"[Analyzer] Failed to read file {rel_file_path}: {read_err}")
                    errors_list.append({"file": rel_file_path, "error": f"Read error: {str(read_err)}"})
                    continue

                # Match Language Parser
                matched_parser = None
                for parser in self.parsers:
                    if parser.supports(ext):
                        matched_parser = parser
                        break

                language_name = matched_parser.language_name if matched_parser else "Other/Config"
                if matched_parser:
                    detected_languages.add(matched_parser.language_name)

                files_info.append(
                    FileInfo(
                        file_path=rel_file_path,
                        language=language_name,
                        size_bytes=size_bytes,
                        line_count=line_count,
                        is_dependency_file=is_dep,
                        is_config_file=is_cfg,
                    )
                )

                # Parse file content if parser matched
                if matched_parser:
                    try:
                        parsed_data = matched_parser.parse(abs_file_path, rel_file_path, content)
                        imports_list.extend(parsed_data.imports)
                        functions_list.extend(parsed_data.functions)
                        classes_list.extend(parsed_data.classes)
                        apis_list.extend(parsed_data.apis)
                        endpoints_list.extend(parsed_data.endpoints)
                        security_list.extend(parsed_data.security_constructs)
                    except Exception as parse_err:
                        logger.error(f"[Analyzer] Error parsing file {rel_file_path}: {parse_err}", exc_info=True)
                        errors_list.append({"file": rel_file_path, "error": f"Parse error: {str(parse_err)}"})

                # Dependency manifest parsing
                if is_dep:
                    try:
                        pkgs = DependencyParser.parse_manifest(abs_file_path, rel_file_path, content)
                        packages_list.extend(pkgs)
                    except Exception as dep_err:
                        logger.warning(f"[Analyzer] Error parsing dependency manifest {rel_file_path}: {dep_err}")

                # Env file parsing
                if file_name.lower().startswith(".env"):
                    try:
                        env_sec = DependencyParser.parse_env_file(rel_file_path, content)
                        security_list.extend(env_sec)
                    except Exception as env_err:
                        logger.warning(f"[Analyzer] Error parsing env file {rel_file_path}: {env_err}")

        duration_ms = int((time.time() - start_time) * 1000)
        logger.info(f"[Analyzer] Completed analysis for repository ID: {repository_id} in {duration_ms}ms. Total files: {len(files_info)}")

        return AnalysisResult(
            repository_id=repository_id,
            languages=sorted(list(detected_languages)),
            files=files_info,
            imports=imports_list,
            packages=packages_list,
            functions=functions_list,
            classes=classes_list,
            apis=apis_list,
            endpoints=endpoints_list,
            security_relevant_constructs=security_list,
            errors=errors_list,
        )
