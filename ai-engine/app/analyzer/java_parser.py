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


class JavaParser(BaseLanguageParser):
    @property
    def language_name(self) -> str:
        return "Java"

    @property
    def supported_extensions(self) -> List[str]:
        return [".java"]

    def parse(self, file_path: str, relative_path: str, content: str) -> FileAnalysisData:
        data = FileAnalysisData()
        lines = content.splitlines()

        for idx, line in enumerate(lines, 1):
            sline = line.strip()
            if not sline or sline.startswith("//") or sline.startswith("/*") or sline.startswith("*"):
                continue

            # 1. Imports
            import_match = re.search(r"^import\s+([\w\.]+);", sline)
            if import_match:
                pkg_name = import_match.group(1)
                data.imports.append(
                    ImportItem(
                        file_path=relative_path,
                        module=pkg_name,
                        is_external=not pkg_name.startswith("com.mycompany"),
                    )
                )

            # 2. Classes & Interfaces
            class_match = re.search(
                r"\b(public|protected|private)?\s*(static\s+)?(class|interface|enum)\s+([a-zA-Z_$]\w*)(?:\s+extends\s+([a-zA-Z_$]\w*))?",
                sline,
            )
            if class_match:
                kind = class_match.group(3)
                name = class_match.group(4)
                base = [class_match.group(5)] if class_match.group(5) else []
                data.classes.append(
                    ClassSymbol(
                        file_path=relative_path,
                        name=f"{kind.capitalize()}:{name}" if kind != "class" else name,
                        line_number=idx,
                        base_classes=base,
                    )
                )

            # 3. Method definitions
            method_match = re.search(
                r"\b(public|protected|private)\s+[\w<>,\[\]\s]+\s+([a-zA-Z_$]\w*)\s*\(([^)]*)\)\s*(?:throws\s+[\w,\s]+)?\s*\{?",
                sline,
            )
            if method_match:
                method_name = method_match.group(2)
                if method_name not in ["if", "for", "while", "switch", "catch"]:
                    raw_params = method_match.group(3)
                    params = [p.strip().split()[-1] for p in raw_params.split(",") if p.strip()]
                    data.functions.append(
                        FunctionSymbol(
                            file_path=relative_path,
                            name=method_name,
                            line_number=idx,
                            params=params,
                        )
                    )

            # 4. Spring / JAX-RS Annotations (HTTP Endpoints)
            endpoint_match = re.search(
                r"@(Get|Post|Put|Delete|Patch|Request)Mapping\(\s*(?:value\s*=\s*)?['\"]([^'\"]+)['\"]",
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
                        framework="Spring Boot",
                    )
                )

            # 5. Security & Framework Constructs
            # Authentication
            if re.search(r"(@PreAuthorize|SecurityContextHolder|PasswordEncoder|JwtDecoder|AuthenticationManager)", sline):
                data.security_constructs.append(
                    SecurityConstruct(
                        file_path=relative_path,
                        line_number=idx,
                        category="AUTHENTICATION",
                        description="Spring Security or JWT authentication construct",
                        code_snippet=sline[:120],
                    )
                )

            # Database Query (JPA @Query / JDBC / Hibernate)
            elif re.search(r"(@Query\(|jdbcTemplate\.|entityManager\.|SELECT\s+.*?\s+FROM|INSERT\s+INTO)", sline, re.IGNORECASE):
                data.security_constructs.append(
                    SecurityConstruct(
                        file_path=relative_path,
                        line_number=idx,
                        category="DATABASE_QUERY",
                        description="SQL query string or JPA/Hibernate database operation",
                        code_snippet=sline[:120],
                    )
                )

            # Environment / System Properties
            elif re.search(r"(System\.getenv|@Value\(|Environment\.getProperty)", sline):
                data.security_constructs.append(
                    SecurityConstruct(
                        file_path=relative_path,
                        line_number=idx,
                        category="ENV_VAR",
                        description="Java System environment variable or Spring @Value lookup",
                        code_snippet=sline[:120],
                    )
                )

        return data
