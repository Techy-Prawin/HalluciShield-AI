import re
from typing import List
from app.analyzer.javascript_parser import JavaScriptParser
from app.analyzer.base_parser import FileAnalysisData
from app.analyzer.models import ClassSymbol, FunctionSymbol, HttpEndpoint


class TypeScriptParser(JavaScriptParser):
    @property
    def language_name(self) -> str:
        return "TypeScript"

    @property
    def supported_extensions(self) -> List[str]:
        return [".ts", ".tsx", ".cts", ".mts"]

    def parse(self, file_path: str, relative_path: str, content: str) -> FileAnalysisData:
        # Utilize base JavaScript parsing logic
        data = super().parse(file_path, relative_path, content)
        lines = content.splitlines()

        # Perform TypeScript-specific enhancements (interfaces, decorators, NestJS/Routing decorators)
        for idx, line in enumerate(lines, 1):
            sline = line.strip()

            # TypeScript InterfaceDef (categorized with classes for symbol indexing)
            if sline.startswith("interface ") or sline.startswith("export interface "):
                iface_match = re.search(r"\binterface\s+([a-zA-Z_$]\w*)", sline)
                if iface_match:
                    name = iface_match.group(1)
                    if not any(c.name == name for c in data.classes):
                        data.classes.append(
                            ClassSymbol(
                                file_path=relative_path,
                                name=f"Interface:{name}",
                                line_number=idx,
                            )
                        )

            # NestJS / TS Decorators (@Get(), @Post(), @Controller())
            decorator_endpoint = re.search(
                r"@(Get|Post|Put|Delete|Patch|Options|Head)\(\s*['\"]([^'\"]*)['\"]",
                sline,
                re.IGNORECASE,
            )
            if decorator_endpoint:
                data.endpoints.append(
                    HttpEndpoint(
                        file_path=relative_path,
                        line_number=idx,
                        http_method=decorator_endpoint.group(1).upper(),
                        route_path=decorator_endpoint.group(2) or "/",
                        framework="NestJS",
                    )
                )

        return data
