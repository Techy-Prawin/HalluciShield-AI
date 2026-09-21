from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class FileInfo(BaseModel):
    file_path: str
    language: str
    size_bytes: int
    line_count: int
    is_dependency_file: bool = False
    is_config_file: bool = False


class ImportItem(BaseModel):
    file_path: str
    module: str
    name: Optional[str] = None
    alias: Optional[str] = None
    is_external: bool = True


class PackageReference(BaseModel):
    file_path: str
    package_name: str
    version_spec: Optional[str] = None
    ecosystem: str  # npm, PyPI, Maven, Gradle, etc.
    is_dev_dependency: bool = False


class FunctionSymbol(BaseModel):
    file_path: str
    name: str
    line_number: int
    async_def: bool = False
    params: List[str] = Field(default_factory=list)
    class_name: Optional[str] = None


class ClassSymbol(BaseModel):
    file_path: str
    name: str
    line_number: int
    base_classes: List[str] = Field(default_factory=list)


class ApiCall(BaseModel):
    file_path: str
    line_number: int
    target: str
    method: Optional[str] = None
    url_pattern: Optional[str] = None


class HttpEndpoint(BaseModel):
    file_path: str
    line_number: int
    http_method: str
    route_path: str
    framework: str  # FastAPI, Express, Spring, Flask, etc.


class SecurityConstruct(BaseModel):
    file_path: str
    line_number: int
    category: str  # AUTHENTICATION, DATABASE_QUERY, ENV_VAR, SECRET_HARDCODED, INSECURE_METHOD
    description: str
    code_snippet: Optional[str] = None
    raw_details: Dict[str, Any] = Field(default_factory=dict)


class AnalysisResult(BaseModel):
    repository_id: str
    languages: List[str] = Field(default_factory=list)
    files: List[FileInfo] = Field(default_factory=list)
    imports: List[ImportItem] = Field(default_factory=list)
    packages: List[PackageReference] = Field(default_factory=list)
    functions: List[FunctionSymbol] = Field(default_factory=list)
    classes: List[ClassSymbol] = Field(default_factory=list)
    apis: List[ApiCall] = Field(default_factory=list)
    security_relevant_constructs: List[SecurityConstruct] = Field(default_factory=list)
    endpoints: List[HttpEndpoint] = Field(default_factory=list)
    errors: List[Dict[str, str]] = Field(default_factory=list)
