"""
Shared Docker workspace access tests.

Proves the AI engine can consume the workspace layout the backend materializes
on the shared named volume (`/workspace/runs/<scanId>/`):
- `validate_workspace_path` confines analysis to the configured workspace root.
- The analyzer/agents read files from a backend-created run directory.
- Endpoints accept an in-root run path and reject paths outside the root.
"""

import json
import os
import shutil
import tempfile
import pytest

from fastapi import HTTPException
from fastapi.testclient import TestClient
from app.main import app
from app.security import validate_workspace_path
from app.analyzer.engine import RepositoryAnalyzer
from app.agents.dependency_agent import DependencyAnalysisAgent
from app.agents.models import DependencyAnalysisResponse

client = TestClient(app)


@pytest.fixture
def shared_workspace():
    """
    Emulate the backend materializing `/workspace/runs/<scanId>/` inside a
    temp root (docker-compose mounts the same named volume on both services;
    locally HALLUCISHIELD_WORKSPACE_ROOT points the AI engine at that root).
    Realpaths are returned so Windows 8.3 short-name aliases never leak into
    path-equality assertions.
    """
    root = os.path.realpath(tempfile.mkdtemp(prefix="hsh_workspace_"))
    run_dir = os.path.join(root, "runs", "scan-abc123")
    os.makedirs(run_dir, exist_ok=True)

    with open(os.path.join(run_dir, "package.json"), "w", encoding="utf-8") as f:
        json.dump({"name": "shared-app", "dependencies": {"express": "^4.18.0"}}, f)

    with open(os.path.join(run_dir, "app.ts"), "w", encoding="utf-8") as f:
        f.write("import express from 'express';\nconst app = express();\n")

    yield root, run_dir
    shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def outside_workspace():
    """A sibling directory outside the shared workspace root."""
    outside = os.path.realpath(tempfile.mkdtemp(prefix="hsh_outside_"))
    yield os.path.join(outside, "elsewhere")
    shutil.rmtree(outside, ignore_errors=True)


def test_validate_workspace_path_allows_in_root(monkeypatch, shared_workspace):
    root, run_dir = shared_workspace
    monkeypatch.setenv("HALLUCISHIELD_WORKSPACE_ROOT", root)

    safe = validate_workspace_path(run_dir)
    # Backend passes /workspace/runs/<scanId>; resolution stays canonical.
    assert safe == run_dir


def test_validate_workspace_path_rejects_outside_root(monkeypatch, shared_workspace, outside_workspace):
    root, _ = shared_workspace
    monkeypatch.setenv("HALLUCISHIELD_WORKSPACE_ROOT", root)

    with pytest.raises(HTTPException) as exc:
        validate_workspace_path(outside_workspace)
    assert exc.value.status_code == 403
    assert "workspace root" in exc.value.detail


def test_validate_workspace_path_rejects_traversal(monkeypatch, shared_workspace):
    root, run_dir = shared_workspace
    monkeypatch.setenv("HALLUCISHIELD_WORKSPACE_ROOT", root)

    with pytest.raises(HTTPException) as exc:
        validate_workspace_path(run_dir + "/../../escape")
    assert exc.value.status_code == 400
    assert "Path traversal" in exc.value.detail


def test_validate_workspace_path_unrestricted_without_root(shared_workspace):
    """Without the env var the engine keeps its historical permissive behavior."""
    _, run_dir = shared_workspace
    assert validate_workspace_path(run_dir) == run_dir


def test_repository_analyzer_reads_backend_run_workspace(shared_workspace):
    _, run_dir = shared_workspace
    analyzer = RepositoryAnalyzer()
    result = analyzer.analyze_repository("scan-abc123", run_dir)

    assert result.repository_id == "scan-abc123"
    files = {f.file_path for f in result.files}
    assert "package.json" in files
    assert "app.ts" in files
    assert any(p.package_name == "express" for p in result.packages)


def test_dependency_agent_accesses_shared_run_workspace(shared_workspace):
    _, run_dir = shared_workspace
    agent = DependencyAnalysisAgent()
    response = agent.analyze_dependencies("scan-abc123", run_dir)

    assert isinstance(response, DependencyAnalysisResponse)
    assert response.repository_id == "scan-abc123"
    assert response.dependencies_scanned > 0


def test_endpoint_accepts_in_root_run_workspace(monkeypatch, shared_workspace):
    root, run_dir = shared_workspace
    monkeypatch.setenv("HALLUCISHIELD_WORKSPACE_ROOT", root)

    response = client.post(
        "/api/v1/dependency/analyze",
        json={"repository_id": "scan-abc123", "workspace_path": run_dir},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["repository_id"] == "scan-abc123"
    assert data["dependencies_scanned"] > 0


def test_endpoint_rejects_workspace_outside_root(
    monkeypatch, shared_workspace, outside_workspace
):
    root, _ = shared_workspace
    monkeypatch.setenv("HALLUCISHIELD_WORKSPACE_ROOT", root)

    response = client.post(
        "/api/v1/dependency/analyze",
        json={"repository_id": "scan-evil", "workspace_path": outside_workspace},
    )
    assert response.status_code == 403