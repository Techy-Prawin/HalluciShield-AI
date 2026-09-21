import re
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


class JavaScriptParser(BaseLanguageParser):
    @property
    def language_name(self) -> str:
        return "JavaScript"

    @property
    def supported_extensions(self) -> List[str]:
        return [".js", ".jsx", ".mjs", ".cjs"]

    def parse(self, file_path: str, relative_path: str, content: str) -> FileAnalysisData:
        data = FileAnalysisData()
        lines = content.splitlines()

        for idx, line in enumerate(lines, 1):
            sline = line.strip()
            if not sline or sline.startswith("//") or sline.startswith("/*") or sline.startswith("*"):
                continue

            # 1. Imports / Require
            import_match = re.search(r"import\s+.*?\s+from\s+['\"]([^'\"]+)['\"]", sline)
            if import_match:
                module_name = import_match.group(1)
                data.imports.append(
                    ImportItem(
                        file_path=relative_path,
                        module=module_name,
                        is_external=not module_name.startswith("."),
                    )
                )
            else:
                require_match = re.search(r"require\(\s*['\"]([^'\"]+)['\"]\s*\)", sline)
                if require_match:
                    module_name = require_match.group(1)
                    data.imports.append(
                        ImportItem(
                            file_path=relative_path,
                            module=module_name,
                            is_external=not module_name.startswith("."),
                        )
                    )

            # 2. Functions (Standard, Arrow, Async)
            func_match = re.search(r"\b(async\s+)?function\s+([a-zA-Z_$]\w*)", sline)
            if func_match:
                data.functions.append(
                    FunctionSymbol(
                        file_path=relative_path,
                        name=func_match.group(2),
                        line_number=idx,
                        async_def=bool(func_match.group(1)),
                    )
                )
            else:
                arrow_match = re.search(r"\b(const|let|var)\s+([a-zA-Z_$]\w*)\s*=\s*(async\s*)?\(.*?\)\s*=>", sline)
                if arrow_match:
                    data.functions.append(
                        FunctionSymbol(
                            file_path=relative_path,
                            name=arrow_match.group(2),
                            line_number=idx,
                            async_def=bool(arrow_match.group(3)),
                        )
                    )

            # 3. Classes
            class_match = re.search(r"\bclass\s+([a-zA-Z_$]\w*)(?:\s+extends\s+([a-zA-Z_$]\w*))?", sline)
            if class_match:
                bases = [class_match.group(2)] if class_match.group(2) else []
                data.classes.append(
                    ClassSymbol(
                        file_path=relative_path,
                        name=class_match.group(1),
                        line_number=idx,
                        base_classes=bases,
                    )
                )

            # 4. HTTP Endpoints (Express / Connect / Koa)
            endpoint_match = re.search(
                r"\b(?:app|router)\.(get|post|put|delete|patch|options|head|use)\(\s*['\"]([^'\"]+)['\"]",
                sline,
                re.IGNORECASE,
            )
            if endpoint_match:
                data.endpoints.append(
                    HttpEndpoint(
                        file_path=relative_path,
                        line_number=idx,
                        http_method=endpoint_match.group(1).upper(),
                        route_path=endpoint_match.group(2),
                        framework="Express",
                    )
                )

            # 4b. Method Calls (e.g., jwt.verify(), requests.get(), fs.readFileSync())
            method_call_match = re.search(r"\b([a-zA-Z_$]\w*)\.([a-zA-Z_$]\w*)\s*\(", sline)
            if method_call_match:
                target_obj = method_call_match.group(1)
                method_name = method_call_match.group(2)
                # Skip common built-ins and control flow
                if target_obj not in ("console", "process", "module", "exports", "window", "document"):
                    data.functions.append(
                        FunctionSymbol(
                            file_path=relative_path,
                            name=f"{target_obj}.{method_name}",
                            line_number=idx,
                            class_name=target_obj,
                        )
                    )

            # 5. API Calls (fetch, axios)
            api_match = re.search(r"\b(fetch|axios\.get|axios\.post|axios\.put|axios\.delete|axios)\s*\(", sline)
            if api_match:
                target_name = api_match.group(1)
                method = "GET"
                if "." in target_name:
                    method = target_name.split(".")[-1].upper()
                data.apis.append(
                    ApiCall(
                        file_path=relative_path,
                        line_number=idx,
                        target=target_name,
                        method=method,
                    )
                )

            # 6. Security Constructs
            # Authentication
            if re.search(r"\b(jwt\.(verify|sign)|bcrypt\.(compare|hash)|passport\.authenticate|argon2\.)\b", sline):
                data.security_constructs.append(
                    SecurityConstruct(
                        file_path=relative_path,
                        line_number=idx,
                        category="AUTHENTICATION",
                        description="Authentication token or hashing operation",
                        code_snippet=sline[:120],
                    )
                )

            # Database Queries
            elif re.search(r"\b(\.query\(|pool\.query|db\.exec|prisma\.\w+\.|knex\(|\.find\()\b", sline):
                data.security_constructs.append(
                    SecurityConstruct(
                        file_path=relative_path,
                        line_number=idx,
                        category="DATABASE_QUERY",
                        description="Database query execution or ORM call",
                        code_snippet=sline[:120],
                    )
                )

            # Environment Variables
            elif re.search(r"\bprocess\.env\.([a-zA-Z0-9_]+)\b", sline):
                data.security_constructs.append(
                    SecurityConstruct(
                        file_path=relative_path,
                        line_number=idx,
                        category="ENV_VAR",
                        description="Node.js process.env environment variable access",
                        code_snippet=sline[:120],
                    )
                )

            # Hardcoded Secrets
            elif re.search(r"\b(secret|password|apiKey|token)\s*:\s*['\"][^'\"]+['\"]", sline, re.IGNORECASE):
                data.security_constructs.append(
                    SecurityConstruct(
                        file_path=relative_path,
                        line_number=idx,
                        category="SECRET_HARDCODED",
                        description="Potential hardcoded secret or API token key in object literal",
                        code_snippet=sline[:120],
                    )
                )

        return data
