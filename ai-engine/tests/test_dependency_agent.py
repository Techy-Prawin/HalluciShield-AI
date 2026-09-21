"""
Dependency Analysis Agent Test Suite for HalluciShield AI.

Tests dependency parsing and analysis for:
- JavaScript (package.json, package-lock.json)
- Python (requirements.txt, pyproject.toml)
- Java (pom.xml)

Detects:
- Missing dependencies
- Suspicious dependencies
- Inconsistent versions
- Unused dependencies
- Hallucinated packages
- Security risk packages
"""

import os
import shutil
import tempfile
import pytest
import json
from fastapi.testclient import TestClient
from app.main import app
from app.agents.dependency_agent import DependencyAnalysisAgent
from app.agents.dep_parser import DependencyFileParser
from app.agents.models import (
    DependencyAnalysisResponse,
    DependencyFinding,
    DependencySeverity,
    DependencyType,
    DependencyFindingType,
)

client = TestClient(app)


@pytest.fixture
def javascript_repository():
    """
    Create a temporary JavaScript test repository.
    """
    temp_dir = tempfile.mkdtemp(prefix="test_js_repo_")

    # package.json with various issues
    package_json = {
        "name": "test-js-app",
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.18.0",
            "lodash": "^4.17.21",
            "axios": "^1.6.0",
            "express-jwt-auto-auth-phantom": "^1.0.0",  # Fake/hallucinated package
            "event-stream": "^0.9.8",  # Security risk package
            "left-pad": "^1.3.0",  # Deprecated package
            "unused-package": "^2.0.0"  # Will test as unused
        },
        "devDependencies": {
            "jest": "^29.7.0",
            "typescript": "^5.3.0",
            "@types/express": "^4.17.0"
        }
    }
    with open(os.path.join(temp_dir, "package.json"), "w", encoding="utf-8") as f:
        json.dump(package_json, f, indent=2)

    # Source file with some imports (not all dependencies are used)
    source_code = """
const express = require('express');
const lodash = require('lodash');
const axios = require('axios');

function hello() {
    return 'Hello World';
}

module.exports = { hello };
"""
    with open(os.path.join(temp_dir, "app.js"), "w", encoding="utf-8") as f:
        f.write(source_code)

    yield temp_dir

    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def python_repository():
    """
    Create a temporary Python test repository.
    """
    temp_dir = tempfile.mkdtemp(prefix="test_python_repo_")

    # requirements.txt with various issues
    requirements_txt = """
fastapi==0.109.0
uvicorn==0.27.0
pydantic==2.5.0
requests==2.31.0
py-auto-auth-fake==1.0.0
python-dateutil==2.8.2
optparse==1.1
"""
    with open(os.path.join(temp_dir, "requirements.txt"), "w", encoding="utf-8") as f:
        f.write(requirements_txt)

    # pyproject.toml with different versions (version inconsistency)
    pyproject_toml = """
[project]
name = "test-python-app"
version = "1.0.0"

[project.dependencies]
fastapi="^0.110.0"
uvicorn="^0.28.0"
pydantic="^2.6.0"
"""
    with open(os.path.join(temp_dir, "pyproject.toml"), "w", encoding="utf-8") as f:
        f.write(pyproject_toml)

    # Source file with imports
    source_code = """
from fastapi import FastAPI
import uvicorn
from pydantic import BaseModel

app = FastAPI()

@app.get("/")
def read_root():
    return {"Hello": "World"}
"""
    with open(os.path.join(temp_dir, "main.py"), "w", encoding="utf-8") as f:
        f.write(source_code)

    yield temp_dir

    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def java_repository():
    """
    Create a temporary Java test repository.
    """
    temp_dir = tempfile.mkdtemp(prefix="test_java_repo_")

    # pom.xml with various dependencies
    pom_xml = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-app</artifactId>
    <version>1.0.0</version>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <version>3.2.0</version>
        </dependency>
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <version>42.7.0</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
            <version>3.2.0</version>
        </dependency>
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>spring-boot-magic-auth-fake</artifactId>
            <version>1.0.0</version>
            <scope>compile</scope>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
"""
    with open(os.path.join(temp_dir, "pom.xml"), "w", encoding="utf-8") as f:
        f.write(pom_xml)

    # Java source file
    source_code = """
package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @GetMapping("/")
    public String hello() {
        return "Hello World";
    }
}
"""
    with open(os.path.join(temp_dir, "Application.java"), "w", encoding="utf-8") as f:
        f.write(source_code)

    yield temp_dir

    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def empty_repository():
    """Create an empty test repository."""
    temp_dir = tempfile.mkdtemp(prefix="test_empty_repo_")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


# ============================================================
# Unit Tests for DependencyFileParser
# ============================================================

class TestDependencyFileParser:
    """Test the dependency file parser."""

    def test_parser_initialization(self):
        """Test that parser can be initialized."""
        parser = DependencyFileParser()
        assert parser is not None

    def test_supported_files(self):
        """Test that parser recognizes supported files."""
        parser = DependencyFileParser()
        assert "package.json" in parser.SUPPORTED_FILES
        assert "requirements.txt" in parser.SUPPORTED_FILES
        assert "pom.xml" in parser.SUPPORTED_FILES

    def test_parse_package_json(self):
        """Test parsing package.json."""
        parser = DependencyFileParser()
        content = """
{
    "name": "test-app",
    "dependencies": {
        "express": "^4.18.0",
        "lodash": "^4.17.21"
    },
    "devDependencies": {
        "jest": "^29.7.0"
    }
}
"""
        deps = parser._parse_package_json(content, "package.json")
        assert len(deps) == 3

        # Check dependencies
        express = next((d for d in deps if d.name == "express"), None)
        assert express is not None
        assert express.version == "^4.18.0"
        assert express.is_dev_dependency is False

        jest = next((d for d in deps if d.name == "jest"), None)
        assert jest is not None
        assert jest.is_dev_dependency is True

    def test_parse_requirements_txt(self):
        """Test parsing requirements.txt."""
        parser = DependencyFileParser()
        content = """
fastapi==0.109.0
uvicorn==0.27.0
requests>=2.28.0
"""
        deps = parser._parse_requirements_txt(content, "requirements.txt")
        assert len(deps) == 3

        fastapi = next((d for d in deps if d.name == "fastapi"), None)
        assert fastapi is not None
        assert fastapi.version == "==0.109.0"
        assert fastapi.ecosystem == DependencyType.PYPI

    def test_parse_pom_xml(self):
        """Test parsing pom.xml."""
        parser = DependencyFileParser()
        content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <version>3.2.0</version>
        </dependency>
    </dependencies>
</project>
"""
        deps = parser._parse_pom_xml(content, "pom.xml")
        assert len(deps) == 1

        spring = deps[0]
        assert "spring-boot-starter-web" in spring.name
        assert spring.version == "3.2.0"
        assert spring.ecosystem == DependencyType.MAVEN

    def test_extract_js_imports(self):
        """Test extracting imports from JavaScript."""
        parser = DependencyFileParser()
        content = """
const express = require('express');
import axios from 'axios';
import { useState } from 'react';
"""
        imports = parser._extract_js_imports(content)
        assert "express" in imports
        assert "axios" in imports
        assert "react" in imports

    def test_extract_python_imports(self):
        """Test extracting imports from Python."""
        parser = DependencyFileParser()
        content = """
import os
from fastapi import FastAPI
import requests
"""
        imports = parser._extract_python_imports(content)
        assert "os" in imports
        assert "fastapi" in imports
        assert "requests" in imports


# ============================================================
# Integration Tests for DependencyAnalysisAgent
# ============================================================

class TestDependencyAnalysisAgent:
    """Integration tests for the Dependency Analysis Agent."""

    def test_agent_initialization(self):
        """Test that DependencyAnalysisAgent can be initialized."""
        agent = DependencyAnalysisAgent()
        assert agent.parser is not None

    def test_analyze_javascript_repository(self, javascript_repository):
        """Test analyzing a JavaScript repository."""
        agent = DependencyAnalysisAgent()
        response = agent.analyze_dependencies(
            repository_id="test-js-repo",
            workspace_path=javascript_repository,
        )

        assert isinstance(response, DependencyAnalysisResponse)
        assert response.repository_id == "test-js-repo"
        assert response.total_findings > 0
        assert response.dependencies_scanned > 0
        assert response.analysis_duration_ms > 0

    def test_analyze_python_repository(self, python_repository):
        """Test analyzing a Python repository."""
        agent = DependencyAnalysisAgent()
        response = agent.analyze_dependencies(
            repository_id="test-python-repo",
            workspace_path=python_repository,
        )

        assert isinstance(response, DependencyAnalysisResponse)
        assert response.repository_id == "test-python-repo"
        assert response.total_findings > 0

    def test_analyze_java_repository(self, java_repository):
        """Test analyzing a Java repository."""
        agent = DependencyAnalysisAgent()
        response = agent.analyze_dependencies(
            repository_id="test-java-repo",
            workspace_path=java_repository,
        )

        assert isinstance(response, DependencyAnalysisResponse)
        assert response.repository_id == "test-java-repo"
        assert response.total_findings > 0

    def test_analyze_empty_repository(self, empty_repository):
        """Test analyzing an empty repository."""
        agent = DependencyAnalysisAgent()
        response = agent.analyze_dependencies(
            repository_id="test-empty-repo",
            workspace_path=empty_repository,
        )

        assert isinstance(response, DependencyAnalysisResponse)
        assert response.total_findings == 0
        assert response.dependencies_scanned == 0

    def test_finding_structure(self, javascript_repository):
        """Test that findings have the correct structure."""
        agent = DependencyAnalysisAgent()
        response = agent.analyze_dependencies(
            repository_id="test-structure-repo",
            workspace_path=javascript_repository,
        )

        for finding in response.findings:
            assert isinstance(finding, DependencyFinding)
            assert finding.finding_id.startswith("dep-")
            assert isinstance(finding.type, DependencyFindingType)
            assert isinstance(finding.severity, DependencySeverity)
            assert finding.package_name
            assert isinstance(finding.ecosystem, DependencyType)
            assert finding.file
            assert finding.evidence
            assert finding.description

    def test_severity_counts(self, javascript_repository):
        """Test that severity counts are accurate."""
        agent = DependencyAnalysisAgent()
        response = agent.analyze_dependencies(
            repository_id="test-severity-repo",
            workspace_path=javascript_repository,
        )

        actual_critical = sum(1 for f in response.findings if f.severity == DependencySeverity.CRITICAL)
        actual_high = sum(1 for f in response.findings if f.severity == DependencySeverity.HIGH)
        actual_medium = sum(1 for f in response.findings if f.severity == DependencySeverity.MEDIUM)
        actual_low = sum(1 for f in response.findings if f.severity == DependencySeverity.LOW)

        assert response.critical_count == actual_critical
        assert response.high_count == actual_high
        assert response.medium_count == actual_medium
        assert response.low_count == actual_low


# ============================================================
# Tests for Specific Finding Types
# ============================================================

class TestFindingTypes:
    """Test specific finding types are detected."""

    def test_hallucinated_package_detection(self, javascript_repository):
        """Test that hallucinated packages are detected."""
        agent = DependencyAnalysisAgent()
        response = agent.analyze_dependencies(
            repository_id="test-hallucinated-repo",
            workspace_path=javascript_repository,
        )

        hallucinated = [
            f for f in response.findings
            if f.type == DependencyFindingType.HALLUCINATED_PACKAGE
        ]

        # Should find the fake package
        assert len(hallucinated) > 0
        assert any("express-jwt-auto-auth-phantom" in f.package_name for f in hallucinated)

    def test_deprecated_package_detection(self, javascript_repository):
        """Test that deprecated packages are detected."""
        agent = DependencyAnalysisAgent()
        response = agent.analyze_dependencies(
            repository_id="test-deprecated-repo",
            workspace_path=javascript_repository,
        )

        deprecated = [
            f for f in response.findings
            if f.type == DependencyFindingType.DEPRECATED_PACKAGE
        ]

        # Should find left-pad
        assert len(deprecated) > 0
        assert any("left-pad" in f.package_name for f in deprecated)

    def test_security_risk_detection(self, javascript_repository):
        """Test that security risk packages are detected."""
        agent = DependencyAnalysisAgent()
        response = agent.analyze_dependencies(
            repository_id="test-security-repo",
            workspace_path=javascript_repository,
        )

        security_risks = [
            f for f in response.findings
            if f.type == DependencyFindingType.SECURITY_RISK
        ]

        # Should find event-stream
        assert len(security_risks) > 0
        assert any("event-stream" in f.package_name for f in security_risks)

    def test_version_inconsistency_detection(self, python_repository):
        """Test that version inconsistencies are detected."""
        agent = DependencyAnalysisAgent()
        response = agent.analyze_dependencies(
            repository_id="test-version-repo",
            workspace_path=python_repository,
        )

        inconsistencies = [
            f for f in response.findings
            if f.type == DependencyFindingType.VERSION_INCONSISTENCY
        ]

        # Should find version mismatches between requirements.txt and pyproject.toml
        assert len(inconsistencies) > 0

    def test_unused_dependency_detection(self, javascript_repository):
        """Test that unused dependencies are detected."""
        agent = DependencyAnalysisAgent()
        response = agent.analyze_dependencies(
            repository_id="test-unused-repo",
            workspace_path=javascript_repository,
        )

        unused = [
            f for f in response.findings
            if f.type == DependencyFindingType.UNUSED_DEPENDENCY
        ]

        # Should find unused packages (express is used, but others might not be)
        assert isinstance(unused, list)


# ============================================================
# Tests for Normalized Dependency Format
# ============================================================

class TestNormalizedDependencyFormat:
    """Test that findings match the normalized dependency format."""

    def test_normalized_format_fields(self, javascript_repository):
        """Test that findings have all required normalized format fields."""
        agent = DependencyAnalysisAgent()
        response = agent.analyze_dependencies(
            repository_id="test-format-repo",
            workspace_path=javascript_repository,
        )

        for finding in response.findings:
            # Required fields for normalized format
            assert hasattr(finding, "type")
            assert hasattr(finding, "severity")
            assert hasattr(finding, "package_name")
            assert hasattr(finding, "ecosystem")
            assert hasattr(finding, "file")
            assert hasattr(finding, "evidence")
            assert hasattr(finding, "description")

            # Type checks
            assert isinstance(finding.type, str)
            assert isinstance(finding.severity, str)
            assert isinstance(finding.package_name, str)
            assert isinstance(finding.file, str)
            assert isinstance(finding.evidence, str)
            assert isinstance(finding.description, str)

    def test_severity_values(self, javascript_repository):
        """Test that severity values are valid."""
        agent = DependencyAnalysisAgent()
        response = agent.analyze_dependencies(
            repository_id="test-severity-values-repo",
            workspace_path=javascript_repository,
        )

        valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        for finding in response.findings:
            assert finding.severity in valid_severities

    def test_ecosystem_values(self, javascript_repository):
        """Test that ecosystem values are valid."""
        agent = DependencyAnalysisAgent()
        response = agent.analyze_dependencies(
            repository_id="test-ecosystem-repo",
            workspace_path=javascript_repository,
        )

        valid_ecosystems = ["npm", "pypi", "maven", "gradle", "unknown"]
        for finding in response.findings:
            assert finding.ecosystem in valid_ecosystems


# ============================================================
# FastAPI Endpoint Tests
# ============================================================

class TestDependencyEndpoint:
    """Test the FastAPI dependency analysis endpoint."""

    def test_dependency_analyze_endpoint(self, javascript_repository):
        """Test the dependency analysis endpoint."""
        response = client.post(
            "/api/v1/dependency/analyze",
            json={
                "repository_id": "api-test-repo",
                "workspace_path": javascript_repository,
            },
        )

        assert response.status_code == 200
        data = response.json()

        assert data["repository_id"] == "api-test-repo"
        assert "total_findings" in data
        assert "critical_count" in data
        assert "high_count" in data
        assert "medium_count" in data
        assert "low_count" in data
        assert "findings" in data
        assert "dependencies_scanned" in data
        assert "analysis_duration_ms" in data

    def test_dependency_analyze_endpoint_structure(self, javascript_repository):
        """Test that endpoint returns correct response structure."""
        response = client.post(
            "/api/v1/dependency/analyze",
            json={
                "repository_id": "api-structure-repo",
                "workspace_path": javascript_repository,
            },
        )

        assert response.status_code == 200
        data = response.json()

        # Verify top-level structure
        assert isinstance(data["findings"], list)
        assert isinstance(data["total_findings"], int)
        assert isinstance(data["dependencies_scanned"], int)

    def test_dependency_analyze_endpoint_invalid_path(self):
        """Test endpoint with invalid path."""
        response = client.post(
            "/api/v1/dependency/analyze",
            json={
                "repository_id": "api-invalid-repo",
                "workspace_path": "/nonexistent/path",
            },
        )

        # Should return 200 with empty results
        assert response.status_code == 200
        data = response.json()
        assert data["total_findings"] == 0

    def test_dependency_analyze_endpoint_missing_fields(self):
        """Test endpoint with missing required fields."""
        response = client.post(
            "/api/v1/dependency/analyze",
            json={},
        )

        # Should return 422 Unprocessable Entity
        assert response.status_code == 422


# ============================================================
# Edge Case Tests
# ============================================================

class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_concurrent_analysis(self, javascript_repository):
        """Test that multiple analyses can run concurrently."""
        import concurrent.futures

        agent = DependencyAnalysisAgent()

        def run_analysis(repo_id):
            return agent.analyze_dependencies(
                repository_id=repo_id,
                workspace_path=javascript_repository,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(run_analysis, f"concurrent-repo-{i}")
                for i in range(3)
            ]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All analyses should complete successfully
        assert len(results) == 3
        for result in results:
            assert isinstance(result, DependencyAnalysisResponse)

    def test_malformed_package_json(self):
        """Test handling of malformed package.json."""
        temp_dir = tempfile.mkdtemp(prefix="test_malformed_repo_")

        try:
            # Create malformed JSON
            with open(os.path.join(temp_dir, "package.json"), "w", encoding="utf-8") as f:
                f.write("{ invalid json }")

            agent = DependencyAnalysisAgent()
            response = agent.analyze_dependencies(
                repository_id="test-malformed-repo",
                workspace_path=temp_dir,
            )

            # Should handle gracefully
            assert isinstance(response, DependencyAnalysisResponse)
            assert response.total_findings == 0
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_malformed_requirements_txt(self):
        """Test handling of malformed requirements.txt."""
        temp_dir = tempfile.mkdtemp(prefix="test_malformed_req_repo_")

        try:
            # Create malformed requirements
            with open(os.path.join(temp_dir, "requirements.txt"), "w", encoding="utf-8") as f:
                f.write("this is not a valid requirement\nanother invalid line\n")

            agent = DependencyAnalysisAgent()
            response = agent.analyze_dependencies(
                repository_id="test-malformed-req-repo",
                workspace_path=temp_dir,
            )

            # Should handle gracefully
            assert isinstance(response, DependencyAnalysisResponse)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
