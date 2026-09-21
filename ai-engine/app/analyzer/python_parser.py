import ast
import re
import logging
from typing import List
from app.analyzer.base_parser import BaseLanguageParser, FileAnalysisData
from app.analyzer.models import (
    ImportItem,
    FunctionSymbol,
    ClassSymbol,
    ApiCall,
    HttpEndpoint,
    SecurityConstruct,
)

logger = logging.getLogger(__name__)


class PythonParser(BaseLanguageParser):
    @property
    def language_name(self) -> str:
        return "Python"

    @property
    def supported_extensions(self) -> List[str]:
        return [".py", ".pyw"]

    def parse(self, file_path: str, relative_path: str, content: str) -> FileAnalysisData:
        data = FileAnalysisData()
        lines = content.splitlines()

        # 1. Try AST parsing first
        try:
            tree = ast.parse(content, filename=relative_path)
            self._visit_ast(tree, relative_path, lines, data)
        except Exception as syntax_err:
            logger.warning(f"[PythonParser] Syntax error parsing {relative_path}: {syntax_err}")
            lineno = getattr(syntax_err, 'lineno', 1) or 1
            snippet = lines[lineno - 1][:120] if lines and lineno <= len(lines) else None
            data.security_constructs.append(
                SecurityConstruct(
                    file_path=relative_path,
                    line_number=lineno,
                    category="MALFORMED_SYNTAX",
                    description=f"Malformed Python syntax: {str(syntax_err)}",
                    code_snippet=snippet,
                )
            )
            # Fallback to regex pattern extraction if AST parsing fails on malformed python
            self._parse_with_regex(content, relative_path, lines, data)

        # 2. Extract security & framework constructs with regex
        self._extract_security_constructs(content, relative_path, lines, data)

        return data

    def _visit_ast(self, tree: ast.AST, rel_path: str, lines: List[str], data: FileAnalysisData):
        for node in ast.walk(tree):
            # Imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    data.imports.append(
                        ImportItem(
                            file_path=rel_path,
                            module=alias.name,
                            alias=alias.asname,
                            is_external=not alias.name.startswith("."),
                        )
                    )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    data.imports.append(
                        ImportItem(
                            file_path=rel_path,
                            module=module,
                            name=alias.name,
                            alias=alias.asname,
                            is_external=not module.startswith("."),
                        )
                    )

            # Classes
            elif isinstance(node, ast.ClassDef):
                bases = [ast.unparse(b) for b in node.bases if hasattr(ast, "unparse")]
                data.classes.append(
                    ClassSymbol(
                        file_path=rel_path,
                        name=node.name,
                        line_number=node.lineno,
                        base_classes=bases,
                    )
                )

            # Functions
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                params = [arg.arg for arg in node.args.args]
                is_async = isinstance(node, ast.AsyncFunctionDef)

                # Check for HTTP Endpoint Decorators (@app.get, @router.post, @app.route)
                for decorator in node.decorator_list:
                    dec_str = ""
                    if hasattr(ast, "unparse"):
                        dec_str = ast.unparse(decorator)
                    elif isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                        dec_str = f"{decorator.func.attr}"

                    endpoint_match = re.search(
                        r"(?:app|router|api)\.(get|post|put|delete|patch|options|head|route)\(\s*['\"]([^'\"]+)['\"]",
                        dec_str,
                        re.IGNORECASE,
                    )
                    if endpoint_match:
                        method = endpoint_match.group(1).upper()
                        route = endpoint_match.group(2)
                        data.endpoints.append(
                            HttpEndpoint(
                                file_path=rel_path,
                                line_number=node.lineno,
                                http_method=method if method != "ROUTE" else "GET/POST",
                                route_path=route,
                                framework="FastAPI/Flask",
                            )
                        )

                data.functions.append(
                    FunctionSymbol(
                        file_path=rel_path,
                        name=node.name,
                        line_number=node.lineno,
                        async_def=is_async,
                        params=params,
                    )
                )

            # Function/Method API Calls
            elif isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    val = ""
                    if isinstance(node.func.value, ast.Name):
                        val = node.func.value.id
                    func_name = f"{val}.{node.func.attr}" if val else node.func.attr

                if func_name in ["requests.get", "requests.post", "httpx.get", "httpx.post", "urllib.request.urlopen", "aiohttp.ClientSession"]:
                    data.apis.append(
                        ApiCall(
                            file_path=rel_path,
                            line_number=node.lineno,
                            target=func_name,
                            method=func_name.split(".")[-1].upper(),
                        )
                    )

    def _parse_with_regex(self, content: str, rel_path: str, lines: List[str], data: FileAnalysisData):
        for idx, line in enumerate(lines, 1):
            sline = line.strip()
            # Regex Function Def
            func_m = re.match(r"^(async\s+)?def\s+([a-zA-Z_]\w*)\s*\(", sline)
            if func_m:
                data.functions.append(
                    FunctionSymbol(
                        file_path=rel_path,
                        name=func_m.group(2),
                        line_number=idx,
                        async_def=bool(func_m.group(1)),
                    )
                )
            # Regex Class Def
            class_m = re.match(r"^class\s+([a-zA-Z_]\w*)", sline)
            if class_m:
                data.classes.append(
                    ClassSymbol(
                        file_path=rel_path,
                        name=class_m.group(1),
                        line_number=idx,
                    )
                )

    def _extract_security_constructs(self, content: str, rel_path: str, lines: List[str], data: FileAnalysisData):
        for idx, line in enumerate(lines, 1):
            sline = line.strip()
            if not sline or sline.startswith("#"):
                continue

            # Authentication / Security
            if re.search(r"\b(jwt\.(encode|decode)|bcrypt\.|passlib\.|hashlib\.|OAuth2|login_required|verify_password)\b", sline):
                data.security_constructs.append(
                    SecurityConstruct(
                        file_path=rel_path,
                        line_number=idx,
                        category="AUTHENTICATION",
                        description="Authentication or token security operation",
                        code_snippet=sline[:120],
                    )
                )

            # Database Query
            elif re.search(r"\b(\.execute\(|\.query\(|objects\.filter\(|select\(|session\.add\(|cursor\.execute)\b", sline):
                data.security_constructs.append(
                    SecurityConstruct(
                        file_path=rel_path,
                        line_number=idx,
                        category="DATABASE_QUERY",
                        description="Database query execution construct",
                        code_snippet=sline[:120],
                    )
                )

            # Environment Variables
            elif re.search(r"\b(os\.getenv|os\.environ|dotenv\.load_dotenv|config\()\b", sline):
                data.security_constructs.append(
                    SecurityConstruct(
                        file_path=rel_path,
                        line_number=idx,
                        category="ENV_VAR",
                        description="Environment variable lookup or configuration load",
                        code_snippet=sline[:120],
                    )
                )

            # Hardcoded Secret / Credential Risk
            elif re.search(r"\b(SECRET_KEY|PASSWORD|API_KEY|PRIVATE_KEY)\s*=\s*['\"][^'\"]+['\"]", sline, re.IGNORECASE):
                data.security_constructs.append(
                    SecurityConstruct(
                        file_path=rel_path,
                        line_number=idx,
                        category="SECRET_HARDCODED",
                        description="Potential hardcoded secret or API key string assignment",
                        code_snippet=sline[:120],
                    )
                )
