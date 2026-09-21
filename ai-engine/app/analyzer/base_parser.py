from abc import ABC, abstractmethod
from typing import List
from app.analyzer.models import (
    ImportItem,
    FunctionSymbol,
    ClassSymbol,
    ApiCall,
    HttpEndpoint,
    SecurityConstruct,
)


class FileAnalysisData:
    def __init__(self):
        self.imports: List[ImportItem] = []
        self.functions: List[FunctionSymbol] = []
        self.classes: List[ClassSymbol] = []
        self.apis: List[ApiCall] = []
        self.endpoints: List[HttpEndpoint] = []
        self.security_constructs: List[SecurityConstruct] = []


class BaseLanguageParser(ABC):
    @property
    @abstractmethod
    def language_name(self) -> str:
        """Name of the programming language handled by this parser."""
        pass

    @property
    @abstractmethod
    def supported_extensions(self) -> List[str]:
        """List of file extensions supported by this parser (e.g. ['.py'])."""
        pass

    def supports(self, file_extension: str) -> bool:
        return file_extension.lower() in [ext.lower() for ext in self.supported_extensions]

    @abstractmethod
    def parse(self, file_path: str, relative_path: str, content: str) -> FileAnalysisData:
        """
        Statically analyze source code content without executing it.
        Return extracted imports, functions, classes, APIs, endpoints, and security constructs.
        """
        pass
