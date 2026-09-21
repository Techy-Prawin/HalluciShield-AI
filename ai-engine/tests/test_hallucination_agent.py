import os
import shutil
import tempfile
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.agents.hallucination_agent import HallucinationDetectionAgent
from app.agents.verification_engine import DeterministicVerificationEngine
from app.agents.models import VerificationStatus, FindingType

client = TestClient(app)


@pytest.fixture
def benchmark_sample_repository():
    """Create a temporary test repository containing 5 distinct test scenarios."""
    temp_dir = tempfile.mkdtemp(prefix="test_halluci_repo_")

    # 1. Valid package ('express') & 2. Fake package ('express-jwt-auto-auth-phantom') in package.json
    pkg_json = """{
  "name": "hallucination-benchmark-app",
  "dependencies": {
    "express": "^4.21.0",
    "express-jwt-auto-auth-phantom": "^1.0.0"
  }
}"""
    with open(os.path.join(temp_dir, "package.json"), "w", encoding="utf-8") as f:
        f.write(pkg_json)

    # 3. Fake API / Phantom Method ('jwt.verifyAndAuthorize')
    # 5. Valid API with unusual usage / signature mismatch (algorithm: 'none')
    js_code = """
const jwt = require('jsonwebtoken');

function handleLogin(req, res) {
    // Fake API / Phantom method call
    const user = jwt.verifyAndAuthorize(req.headers.authorization);
    return res.json(user);
}

function verifyBypass(token) {
    // Valid API with unusual usage / signature mismatch (insecure algorithm: 'none')
    return jwt.verify(token, 'secret', { algorithm: 'none' });
}
"""
    with open(os.path.join(temp_dir, "auth_controller.js"), "w", encoding="utf-8") as f:
        f.write(js_code)

    # 4. Suspicious function with unusual parameters
    py_code = """
import requests

def suspicious_data_fetch():
    # Suspicious function using phantom method on requests
    response = requests.getAndParseJsonAuto("https://api.example.com/data")
    return response
"""
    with open(os.path.join(temp_dir, "fetcher.py"), "w", encoding="utf-8") as f:
        f.write(py_code)

    yield temp_dir

    shutil.rmtree(temp_dir, ignore_errors=True)


def test_scenario_1_valid_package():
    evidence = DeterministicVerificationEngine.verify_package("express", "npm")
    assert evidence.registry_status == "200_OK"
    assert "verified real" in evidence.facts[0].lower()


def test_scenario_2_fake_package():
    evidence = DeterministicVerificationEngine.verify_package("express-jwt-auto-auth-phantom", "npm")
    assert evidence.registry_status == "404_NOT_FOUND"
    assert any("404" in fact for fact in evidence.facts)


def test_scenario_3_fake_api_phantom_method():
    valid, evidence = DeterministicVerificationEngine.verify_method_symbol("jsonwebtoken", "verifyAndAuthorize")
    assert valid is False
    assert evidence.registry_status == "SYMBOL_NOT_FOUND"
    assert "verifyAndAuthorize" in evidence.symbol_name


def test_hallucination_agent_full_detection(benchmark_sample_repository):
    agent = HallucinationDetectionAgent()
    response = agent.detect_hallucinations("benchmark-repo-101", benchmark_sample_repository)

    assert response.repository_id == "benchmark-repo-101"
    assert response.total_findings >= 3
    assert response.confirmed_findings_count >= 2

    # 1. Assert Fake Package finding
    fake_pkg_finding = next((f for f in response.findings if f.type == FindingType.HALLUCINATED_PACKAGE), None)
    assert fake_pkg_finding is not None
    assert fake_pkg_finding.verification_status == VerificationStatus.CONFIRMED
    assert fake_pkg_finding.evidence.registry_status == "404_NOT_FOUND"

    # 2. Assert Fake API / Phantom Method finding
    phantom_method_finding = next((f for f in response.findings if f.type == FindingType.PHANTOM_METHOD), None)
    assert phantom_method_finding is not None
    assert phantom_method_finding.verification_status in [VerificationStatus.CONFIRMED, VerificationStatus.LIKELY]

    # 3. Assert Unsupported Security Assumption / Signature Mismatch finding
    security_finding = next(
        (f for f in response.findings if f.type == FindingType.UNSUPPORTED_SECURITY_ASSUMPTION or f.type == FindingType.SIGNATURE_MISMATCH),
        None
    )
    assert security_finding is not None
    assert security_finding.verification_status == VerificationStatus.CONFIRMED


def test_fastapi_detect_endpoint(benchmark_sample_repository):
    response = client.post(
        "/api/v1/hallucination/detect",
        json={
            "repository_id": "api-benchmark-repo-202",
            "workspace_path": benchmark_sample_repository,
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert data["repository_id"] == "api-benchmark-repo-202"
    assert data["total_findings"] >= 3
    assert len(data["findings"]) >= 3

    # Print example result for verification output display
    print("\n--- EXAMPLE HALLUCINATION DETECTION AGENT RESULT ---")
    import json
    print(json.dumps(data["findings"][0], indent=2))
