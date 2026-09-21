import os
import shutil
import tempfile
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.analyzer.engine import RepositoryAnalyzer
from app.analyzer.python_parser import PythonParser
from app.analyzer.javascript_parser import JavaScriptParser
from app.analyzer.typescript_parser import TypeScriptParser
from app.analyzer.java_parser import JavaParser
from app.analyzer.dependency_parser import DependencyParser

client = TestClient(app)


@pytest.fixture
def temp_repo_workspace():
    """Create a temporary repository directory populated with multi-language code samples."""
    temp_dir = tempfile.mkdtemp(prefix="test_repo_")

    # Python File
    py_code = """
import os
import jwt
from fastapi import FastAPI

app = FastAPI()

class UserService:
    def __init__(self):
        self.secret = os.getenv("JWT_SECRET")

@app.get("/api/v1/users")
async def get_users():
    token = jwt.decode("token", "secret", algorithms=["HS256"])
    db_cursor.execute("SELECT * FROM users")
    return {"status": "ok"}
"""
    with open(os.path.join(temp_dir, "main.py"), "w", encoding="utf-8") as f:
        f.write(py_code)

    # JavaScript File
    js_code = """
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

class AuthController {
    login(req, res) {
        const token = jwt.sign({ user: 'alex' }, process.env.SECRET_KEY);
        pool.query('SELECT * FROM accounts WHERE id = ' + req.params.id);
        res.json({ token });
    }
}

app.post('/api/login', (req, res) => {
    fetch('https://api.external.com/data');
});
"""
    with open(os.path.join(temp_dir, "app.js"), "w", encoding="utf-8") as f:
        f.write(js_code)

    # TypeScript File
    ts_code = """
import { Controller, Get } from '@nestjs/common';

export interface UserDto {
    id: string;
    username: string;
}

@Controller('/users')
export class UserController {
    @Get('/profile')
    getProfile(): UserDto {
        return { id: '1', username: 'alex' };
    }
}
"""
    with open(os.path.join(temp_dir, "user.controller.ts"), "w", encoding="utf-8") as f:
        f.write(ts_code)

    # Java File
    java_code = """
package com.hallucishield.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrderController {
    
    @GetMapping("/api/orders")
    public String getOrders() {
        String dbUrl = System.getenv("DB_URL");
        return "orders";
    }
}
"""
    with open(os.path.join(temp_dir, "OrderController.java"), "w", encoding="utf-8") as f:
        f.write(java_code)

    # package.json
    pkg_json = """{
  "name": "sample-repo",
  "dependencies": {
    "express": "^4.21.0",
    "jsonwebtoken": "^9.0.0"
  },
  "devDependencies": {
    "typescript": "^5.0.0"
  }
}"""
    with open(os.path.join(temp_dir, "package.json"), "w", encoding="utf-8") as f:
        f.write(pkg_json)

    # requirements.txt
    req_txt = """
fastapi==0.115.0
pyjwt>=2.8.0
"""
    with open(os.path.join(temp_dir, "requirements.txt"), "w", encoding="utf-8") as f:
        f.write(req_txt)

    # .env
    env_txt = """
JWT_SECRET=super_secret_jwt_key
PORT=4000
"""
    with open(os.path.join(temp_dir, ".env"), "w", encoding="utf-8") as f:
        f.write(env_txt)

    # Malformed Python File (testing fault tolerance)
    with open(os.path.join(temp_dir, "broken.py"), "w", encoding="utf-8") as f:
        f.write("def broken_syntax(:\n   this is not valid python code!!!")

    yield temp_dir

    # Teardown
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_python_parser():
    parser = PythonParser()
    code = """
import os
import jwt

class User:
    pass

def login():
    secret = os.getenv("API_KEY")
    jwt.decode("token")
"""
    data = parser.parse("test.py", "test.py", code)
    assert any(i.module == "os" for i in data.imports)
    assert any(c.name == "User" for c in data.classes)
    assert any(f.name == "login" for f in data.functions)
    assert any(s.category == "AUTHENTICATION" for s in data.security_constructs)
    assert any(s.category == "ENV_VAR" for s in data.security_constructs)


def test_javascript_parser():
    parser = JavaScriptParser()
    code = """
const express = require('express');
const app = express();

app.get('/api/health', (req, res) => {
    process.env.PORT;
    pool.query('SELECT 1');
});
"""
    data = parser.parse("app.js", "app.js", code)
    assert any(i.module == "express" for i in data.imports)
    assert any(e.route_path == "/api/health" for e in data.endpoints)
    assert any(s.category == "DATABASE_QUERY" for s in data.security_constructs)


def test_typescript_parser():
    parser = TypeScriptParser()
    code = """
export interface Product {
    id: string;
}
"""
    data = parser.parse("product.ts", "product.ts", code)
    assert any("Product" in c.name for c in data.classes)


def test_java_parser():
    parser = JavaParser()
    code = """
package com.demo;
import java.util.List;

public class App {
    public void main() {
        System.getenv("JAVA_HOME");
    }
}
"""
    data = parser.parse("App.java", "App.java", code)
    assert any(c.name == "App" for c in data.classes)
    assert any(f.name == "main" for f in data.functions)


def test_dependency_parser():
    pkg_content = '{"dependencies": {"express": "^4.18.0"}}'
    pkgs = DependencyParser.parse_manifest("package.json", "package.json", pkg_content)
    assert len(pkgs) == 1
    assert pkgs[0].package_name == "express"

    env_content = "SECRET_KEY=12345"
    sec = DependencyParser.parse_env_file(".env", env_content)
    assert len(sec) == 1
    assert sec[0].category == "SECRET_HARDCODED"


def test_repository_analyzer_e2e(temp_repo_workspace):
    analyzer = RepositoryAnalyzer()
    result = analyzer.analyze_repository(
        repository_id="repo-test-100",
        workspace_path=temp_repo_workspace,
    )

    assert result.repository_id == "repo-test-100"
    assert "Python" in result.languages
    assert "JavaScript" in result.languages
    assert "TypeScript" in result.languages
    assert "Java" in result.languages

    assert len(result.files) >= 7
    assert len(result.packages) >= 3
    assert len(result.functions) >= 2
    assert len(result.classes) >= 2
    assert len(result.endpoints) >= 2
    assert len(result.security_relevant_constructs) >= 3

    # Verify malformed file error handling (broken.py captured with MALFORMED_SYNTAX category)
    assert any(s.category == "MALFORMED_SYNTAX" and "broken.py" in s.file_path for s in result.security_relevant_constructs)


def test_analyzer_fastapi_endpoint(temp_repo_workspace):
    response = client.post(
        "/api/v1/analyzer/analyze",
        json={
            "repository_id": "api-test-repo-55",
            "workspace_path": temp_repo_workspace,
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert data["repository_id"] == "api-test-repo-55"
    assert "languages" in data
    assert "files" in data
    assert "imports" in data
    assert "packages" in data
    assert "functions" in data
    assert "classes" in data
    assert "apis" in data
    assert "security_relevant_constructs" in data
