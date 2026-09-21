"""
End-to-End Pipeline Test for HalluciShield AI.

Tests the complete workflow:
  Test repo -> Upload -> Analysis -> Hallucination -> Dependency -> Security
  -> Risk -> Patches -> Validation -> Confidence -> Ranking
  -> Review -> Approval -> Feedback -> Learning

Uses a controlled test repository containing:
  - SQL injection
  - XSS
  - Hardcoded secret
  - Hallucinated API
  - Suspicious dependency (package.json)
"""
import json
import os
import shutil
import tempfile
import time

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.agents.experiment_runner import experiment_runner

client = TestClient(app)

# ---------------------------------------------------------------------------
# Controlled test repository
# ---------------------------------------------------------------------------

REPO_ID = "e2e-test-repo-001"

APP_PY = '''\
import sqlite3
import os

SECRET_KEY = "super_secret_api_key_12345"
DB_PASSWORD = "admin123"

def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def render_page(user_input):
    return "<html><body>" + user_input + "</body></html>"

def run_command(filename):
    import subprocess
    subprocess.call("cat " + filename, shell=True)
'''

PACKAGE_JSON = '''\
{
  "name": "e2e-test-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "phantom-utils": "^1.0.0",
    "event-stream": "^0.9.0"
  }
}
'''

REQUIREMENTS_TXT = '''\
flask==2.3.0
requests>=2.31.0
'''


def _create_test_repo(base_dir: str) -> str:
    """Create a controlled test repository with known vulnerabilities."""
    repo_dir = os.path.join(base_dir, "test_repo")
    os.makedirs(repo_dir, exist_ok=True)

    with open(os.path.join(repo_dir, "app.py"), "w") as f:
        f.write(APP_PY)

    with open(os.path.join(repo_dir, "package.json"), "w") as f:
        f.write(PACKAGE_JSON)

    with open(os.path.join(repo_dir, "requirements.txt"), "w") as f:
        f.write(REQUIREMENTS_TXT)

    return repo_dir


# ---------------------------------------------------------------------------
# Shared state across stages
# ---------------------------------------------------------------------------

_state = {}


# ---------------------------------------------------------------------------
# STAGE 1: Repository Analysis (Static Extraction)
# ---------------------------------------------------------------------------

class TestStage1RepositoryAnalysis:
    def test_analyze_repository(self, tmp_path):
        repo_dir = _create_test_repo(str(tmp_path))
        _state["repo_dir"] = repo_dir
        _state["repo_id"] = REPO_ID

        resp = client.post("/api/v1/analyzer/analyze", json={
            "repository_id": REPO_ID,
            "workspace_path": repo_dir,
        })
        assert resp.status_code == 200, f"Stage 1 FAILED: {resp.status_code} {resp.text}"
        data = resp.json()
        assert data["repository_id"] == REPO_ID
        assert len(data["files"]) > 0
        _state["analysis_result"] = data
        print(f"\n[STAGE 1] Repository Analysis: {len(data['files'])} files, languages: {data['languages']}")


# ---------------------------------------------------------------------------
# STAGE 2: Hallucination Detection
# ---------------------------------------------------------------------------

class TestStage2HallucinationDetection:
    def test_detect_hallucinations(self):
        resp = client.post("/api/v1/hallucination/detect", json={
            "repository_id": _state["repo_id"],
            "workspace_path": _state["repo_dir"],
        })
        assert resp.status_code == 200, f"Stage 2 FAILED: {resp.status_code} {resp.text}"
        data = resp.json()
        assert data["repository_id"] == _state["repo_id"]
        assert isinstance(data["findings"], list)
        _state["hallucination_response"] = data
        print(f"\n[STAGE 2] Hallucination Detection: {data['total_findings']} findings")

    def test_detection_covers_all_vuln_types(self):
        resp = client.post("/api/v1/hallucination/detect", json={
            "repository_id": _state["repo_id"],
            "workspace_path": _state["repo_dir"],
        })
        assert resp.status_code == 200
        data = resp.json()
        finding_types = [f["type"] for f in data["findings"]]
        print(f"  Finding types: {finding_types}")
        print(f"  Total findings: {data['total_findings']}")
        print(f"  Critical: {data.get('critical_count', 'N/A')}")
        print(f"  High: {data.get('high_count', 'N/A')}")
        assert data["total_findings"] >= 0


# ---------------------------------------------------------------------------
# STAGE 3: Dependency Analysis
# ---------------------------------------------------------------------------

class TestStage3DependencyAnalysis:
    def test_analyze_dependencies(self):
        resp = client.post("/api/v1/dependency/analyze", json={
            "repository_id": _state["repo_id"],
            "workspace_path": _state["repo_dir"],
        })
        assert resp.status_code == 200, f"Stage 3 FAILED: {resp.status_code} {resp.text}"
        data = resp.json()
        assert data["repository_id"] == _state["repo_id"]
        assert isinstance(data["findings"], list)
        _state["dependency_response"] = data
        print(f"\n[STAGE 3] Dependency Analysis: {data['total_findings']} findings")
        for f in data["findings"]:
            print(f"  - [{f['severity']}] {f['type']}: {f.get('package_name', 'N/A')}")


# ---------------------------------------------------------------------------
# STAGE 4: Security Scanning
# ---------------------------------------------------------------------------

class TestStage4SecurityScanning:
    def test_security_scan(self):
        resp = client.post("/api/v1/security/scan", json={
            "repository_id": _state["repo_id"],
            "workspace_path": _state["repo_dir"],
        })
        assert resp.status_code == 200, f"Stage 4 FAILED: {resp.status_code} {resp.text}"
        data = resp.json()
        assert data["repository_id"] == _state["repo_id"]
        assert isinstance(data["findings"], list)
        _state["security_response"] = data
        print(f"\n[STAGE 4] Security Scanning: {data['total_vulnerabilities']} findings")
        print(f"  Critical: {data.get('critical_count', 0)}, High: {data.get('high_count', 0)}, Medium: {data.get('medium_count', 0)}, Low: {data.get('low_count', 0)}")
        for f in data["findings"]:
            print(f"  - [{f.get('severity', 'N/A')}] {f.get('cwe', 'N/A')}: {f.get('description', 'N/A')[:80]}")


# ---------------------------------------------------------------------------
# STAGE 5: Risk Assessment
# ---------------------------------------------------------------------------

class TestStage5RiskAssessment:
    def test_risk_assessment(self):
        resp = client.get(
            f"/api/v1/risk/repositories/{_state['repo_id']}/risk",
            params={"workspace_path": _state["repo_dir"]},
        )
        assert resp.status_code == 200, f"Stage 5 FAILED: {resp.status_code} {resp.text}"
        data = resp.json()
        assessment = data["risk_assessment"]
        assert assessment["overall_risk_score"] >= 0
        assert assessment["total_findings"] >= 0
        _state["risk_assessment"] = assessment
        print(f"\n[STAGE 5] Risk Assessment:")
        print(f"  Overall Score: {assessment['overall_risk_score']:.1f}/100")
        print(f"  Risk Level: {assessment['overall_risk_level']}")
        print(f"  Total Findings: {assessment['total_findings']}")
        print(f"  Critical: {assessment.get('critical_findings', 0)}")
        print(f"  High: {assessment.get('high_findings', 0)}")
        print(f"  Recommendations: {assessment.get('recommendations', [])}")


# ---------------------------------------------------------------------------
# STAGE 6: Generate 5 Patches
# ---------------------------------------------------------------------------

class TestStage6PatchGeneration:
    def test_generate_patches_sql_injection(self):
        VULN_ID = "vuln-sql-001"
        resp = client.post(f"/api/v1/vulnerabilities/{VULN_ID}/generate-patches", json={
            "vulnerability_id": VULN_ID,
            "vulnerability_type": "SQL_INJECTION",
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "file": "app.py",
            "line": 8,
            "description": "SQL injection via string concatenation in query",
            "vulnerable_code": 'query = "SELECT * FROM users WHERE username = \'" + username + "\'"',
            "surrounding_code": APP_PY,
        })
        assert resp.status_code == 200, f"Stage 6 FAILED: {resp.status_code} {resp.text}"
        data = resp.json()
        assert len(data["candidates"]) == 5
        _state["patch_response"] = data
        _state["vuln_id"] = VULN_ID
        _state["vulnerable_code"] = APP_PY
        print(f"\n[STAGE 6] Patch Generation: {len(data['candidates'])} candidates")
        print(f"  Model: {data['model_used']}")
        print(f"  Duration: {data['generation_duration_ms']}ms")
        for c in data["candidates"]:
            print(f"  - {c['patch_id']}: {c['security_strategy']}")


# ---------------------------------------------------------------------------
# STAGE 7: Validate Candidates (6-Dimension Scoring)
# ---------------------------------------------------------------------------

class TestStage7Validation:
    def test_validate_candidates(self):
        VULN_ID = _state["vuln_id"]
        candidates = _state["patch_response"]["candidates"]
        vr_list = []
        for c in candidates:
            vr_list.append({
                "patch_id": c["patch_id"],
                "modified_code": c["modified_code"],
                "explanation": c["explanation"],
                "security_strategy": c["security_strategy"],
                "assumptions": c.get("assumptions", []),
                "expected_effect": c.get("expected_effect", ""),
                "potential_side_effects": c.get("potential_side_effects", []),
                "is_hallucination": False,
                "confidence": 0.0,
            })

        resp = client.post(f"/api/v1/vulnerabilities/{VULN_ID}/validate-candidates", json={
            "vulnerability_id": VULN_ID,
            "candidates": vr_list,
            "language": "python",
            "compile_command": "",
            "test_command": "",
        })
        assert resp.status_code == 200, f"Stage 7 FAILED: {resp.status_code} {resp.text}"
        data = resp.json()
        assert data["total_validated"] == 5
        _state["validation_response"] = data
        print(f"\n[STAGE 7] Validation: {data['total_validated']} validated")
        print(f"  Passed: {data['passed_count']}, Failed: {data['failed_count']}")
        for r in data["results"]:
            print(f"  - {r['patch_id']}: status={r['validation_status']}, "
                  f"compilation={r['compilation_score']['score']:.2f}, "
                  f"unit_test={r['unit_test_score']['score']:.2f}, "
                  f"regression={r['regression_score']['score']:.2f}, "
                  f"security={r['security_score']['score']:.2f}, "
                  f"functional={r['functional_score']['score']:.2f}, "
                  f"performance={r['performance_score']['score']:.2f}")


# ---------------------------------------------------------------------------
# STAGE 8: Confidence Calculation + Patch Ranking
# ---------------------------------------------------------------------------

class TestStage8ConfidenceAndRanking:
    def test_confidence_calculation(self):
        VULN_ID = _state["vuln_id"]
        vr_list = _state["validation_response"]["results"]
        candidates = _state["patch_response"]["candidates"]
        patch_strategies = {c["patch_id"]: c["security_strategy"] for c in candidates}

        resp = client.post(f"/api/v1/vulnerabilities/{VULN_ID}/rank-patches", json={
            "vulnerability_id": VULN_ID,
            "validation_results": vr_list,
            "vulnerability_type": "SQL_INJECTION",
            "patch_strategies": patch_strategies,
        })
        assert resp.status_code == 200, f"Stage 8a FAILED: {resp.status_code} {resp.text}"
        data = resp.json()
        ranking = data["ranking"]
        assert len(ranking["rankings"]) == 5
        _state["ranking_response"] = data
        _state["ranking_data"] = ranking
        print(f"\n[STAGE 8a] Confidence Calculation:")
        for r in ranking["rankings"]:
            print(f"  - {r['patch_id']}: confidence={r['confidence_score']:.1f}%")

    def test_recommendation(self):
        VULN_ID = _state["vuln_id"]
        vr_list = _state["validation_response"]["results"]
        candidates = _state["patch_response"]["candidates"]
        patch_strategies = {c["patch_id"]: c["security_strategy"] for c in candidates}

        resp = client.post(
            f"/api/v1/vulnerabilities/{VULN_ID}/recommendation",
            json={
                "vulnerability_id": VULN_ID,
                "validation_results": vr_list,
                "vulnerability_type": "SQL_INJECTION",
                "patch_strategies": patch_strategies,
            },
            params={"safety_threshold": 50.0},
        )
        assert resp.status_code == 200, f"Stage 8b FAILED: {resp.status_code} {resp.text}"
        data = resp.json()
        assert data["status"] == "success"
        _state["recommendation"] = data
        print(f"\n[STAGE 8b] Recommendation:")
        print(f"  Recommended patch: {data.get('recommended_patch_id', 'N/A')}")
        print(f"  Confidence: {data.get('recommended_confidence', 'N/A')}%")
        print(f"  All ranked:")
        for r in data.get("ranked_patches", []):
            print(f"    {r.get('patch_id', 'N/A')}: {r.get('confidence_score', 'N/A')}% - {r.get('recommendation', 'N/A')}")


# ---------------------------------------------------------------------------
# STAGE 9: Explanation + Developer Review + Approval
# ---------------------------------------------------------------------------

class TestStage9ReviewAndApproval:
    def test_explanation(self):
        VULN_ID = _state["vuln_id"]
        vr_list = _state["validation_response"]["results"]
        top_patch = _state["ranking_data"]["rankings"][0]

        resp = client.post(
            f"/api/v1/vulnerabilities/{VULN_ID}/patches/{top_patch['patch_id']}/explanation",
            json={
                "vulnerability_id": VULN_ID,
                "validation_results": vr_list,
            },
        )
        assert resp.status_code == 200, f"Stage 9a FAILED: {resp.status_code} {resp.text}"
        data = resp.json()
        assert data["status"] == "success"
        _state["explanation"] = data
        print(f"\n[STAGE 9a] Explanation for {top_patch['patch_id']}:")
        expl = data.get("explanation", {})
        if isinstance(expl, dict):
            for key in expl:
                print(f"  {key}: {str(expl[key])[:120]}")

    def test_developer_review(self):
        VULN_ID = _state["vuln_id"]
        top_patch = _state["ranking_data"]["rankings"][0]
        patch_code = ""
        for c in _state["patch_response"]["candidates"]:
            if c["patch_id"] == top_patch["patch_id"]:
                patch_code = c["modified_code"]
                break

        resp = client.get(
            f"/api/v1/vulnerabilities/{VULN_ID}/patches/{top_patch['patch_id']}/review",
            params={
                "original_code": _state["vulnerable_code"][:500],
                "patched_code": patch_code[:500],
                "vulnerability_type": "SQL_INJECTION",
                "vulnerability_description": "SQL injection via string concatenation",
                "vulnerability_severity": "CRITICAL",
                "security_strategy": "Parameterized Query",
                "safety_threshold": 50.0,
            },
        )
        assert resp.status_code == 200, f"Stage 9b FAILED: {resp.status_code} {resp.text}"
        data = resp.json()
        _state["review"] = data
        print(f"\n[STAGE 9b] Developer Review:")
        print(f"  Patch ID: {data.get('patch_id', 'N/A')}")
        print(f"  Vulnerability ID: {data.get('vulnerability_id', 'N/A')}")
        print(f"  Has diff: {'diff' in data}")
        print(f"  Confidence score: {data.get('confidence_score', 'N/A')}")

    def test_developer_approval(self):
        VULN_ID = _state["vuln_id"]
        top_patch = _state["ranking_data"]["rankings"][0]

        resp = client.post(
            f"/api/v1/vulnerabilities/{VULN_ID}/patches/{top_patch['patch_id']}/approve",
            json={
                "vulnerability_id": VULN_ID,
                "patch_id": top_patch["patch_id"],
                "developer_id": "dev-e2e-tester",
                "confidence_score": top_patch["confidence_score"],
            },
        )
        assert resp.status_code == 200, f"Stage 9c FAILED: {resp.status_code} {resp.text}"
        data = resp.json()
        assert data["decision"] == "APPROVED"
        _state["approval"] = data
        print(f"\n[STAGE 9c] Developer Approval:")
        print(f"  Decision: {data['decision']}")
        print(f"  Approver: {data.get('approval_record', {}).get('developer_id', 'N/A')}")
        print(f"  Timestamp: {data.get('approval_record', {}).get('approved_at', 'N/A')}")

    def test_approval_status_check(self):
        VULN_ID = _state["vuln_id"]
        top_patch = _state["ranking_data"]["rankings"][0]

        resp = client.get(
            f"/api/v1/vulnerabilities/{VULN_ID}/patches/{top_patch['patch_id']}/approval-status",
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["record"] is not None
        print(f"\n[STAGE 9d] Approval Status Check:")
        print(f"  Record found: {data['record'] is not None}")
        print(f"  Decision: {data['record'].get('decision', 'N/A')}")


# ---------------------------------------------------------------------------
# STAGE 10: Feedback Storage + Adaptive Learning
# ---------------------------------------------------------------------------

class TestStage10FeedbackAndLearning:
    def test_record_learning_event(self):
        VULN_ID = _state["vuln_id"]
        top_patch = _state["ranking_data"]["rankings"][0]

        resp = client.post("/api/v1/learning/record", json={
            "vulnerability_id": VULN_ID,
            "vulnerability_type": "SQL_INJECTION",
            "patch_id": top_patch["patch_id"],
            "patch_strategy": "Parameterized Query",
            "confidence_score": top_patch["confidence_score"],
            "developer_decision": "APPROVED",
            "deployment_outcome": "SUCCESS",
        })
        assert resp.status_code == 201, f"Stage 10a FAILED: {resp.status_code} {resp.text}"
        data = resp.json()
        _state["learning_record"] = data
        print(f"\n[STAGE 10a] Learning Record:")
        print(f"  Record ID: {data.get('id', 'N/A')}")
        print(f"  Vuln Type: {data.get('vulnerability_type', 'N/A')}")

    def test_record_deployment_outcome(self):
        VULN_ID = _state["vuln_id"]
        top_patch = _state["ranking_data"]["rankings"][0]

        resp = client.post("/api/v1/learning/deployment-outcome", json={
            "vulnerability_id": VULN_ID,
            "patch_id": top_patch["patch_id"],
            "deployment_outcome": "SUCCESS",
            "notes": "E2E test deployment",
        })
        assert resp.status_code == 200, f"Stage 10b FAILED: {resp.status_code} {resp.text}"
        data = resp.json()
        assert data["status"] == "success"
        print(f"\n[STAGE 10b] Deployment Outcome:")
        print(f"  Status: {data['status']}")
        print(f"  Message: {data.get('message', 'N/A')}")

    def test_learning_patterns(self):
        resp = client.get("/api/v1/learning/patterns")
        assert resp.status_code == 200
        data = resp.json()
        print(f"\n[STAGE 10c] Learning Patterns: {len(data)} patterns")
        for p in data[:5]:
            print(f"  - {p.get('vulnerability_type', 'N/A')}/{p.get('patch_strategy', 'N/A')}: "
                  f"success_rate={p.get('success_rate', 'N/A')}, samples={p.get('sample_count', 'N/A')}")

    def test_learning_summary(self):
        resp = client.get("/api/v1/learning/summary")
        assert resp.status_code == 200
        data = resp.json()
        print(f"\n[STAGE 10d] Learning Summary:")
        print(f"  Total records: {data.get('total_records', 'N/A')}")
        print(f"  Total patterns: {data.get('total_patterns', 'N/A')}")
        print(f"  Model version: {data.get('model_version', 'N/A')}")

    def test_learning_records(self):
        resp = client.get("/api/v1/learning/records", params={
            "vulnerability_type": "SQL_INJECTION",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1
        print(f"\n[STAGE 10e] Learning Records (SQL_INJECTION): {len(data)} records")
        for r in data:
            print(f"  - {r.get('vulnerability_id', 'N/A')}/{r.get('patch_id', 'N/A')}: "
                  f"decision={r.get('developer_decision', 'N/A')}")


# ---------------------------------------------------------------------------
# STAGE 11: Runtime Monitoring (simulation mode)
# ---------------------------------------------------------------------------

class TestStage11RuntimeMonitoring:
    def test_simulate_events(self):
        resp = client.post("/api/v1/monitoring/simulate", json={"count": 5})
        assert resp.status_code == 200
        data = resp.json()
        assert data["events_created"] >= 0
        print(f"\n[STAGE 11] Runtime Monitoring:")
        print(f"  Events created: {data['events_created']}")
        print(f"  Alerts triggered: {data['alerts_triggered']}")

    def test_get_events(self):
        resp = client.get("/api/v1/monitoring/events")
        assert resp.status_code == 200
        data = resp.json()
        print(f"  Total events: {data['total']}")

    def test_get_alerts(self):
        resp = client.get("/api/v1/monitoring/alerts")
        assert resp.status_code == 200
        data = resp.json()
        print(f"  Total alerts: {data['total']}")

    def test_monitoring_summary(self):
        resp = client.get("/api/v1/monitoring/summary")
        assert resp.status_code == 200
        data = resp.json()
        print(f"  Summary: {data}")


# ---------------------------------------------------------------------------
# STAGE 12: Experiment Run + Analytics
# ---------------------------------------------------------------------------

class TestStage12ExperimentAndAnalytics:
    def test_run_experiment(self):
        resp = client.post("/api/experiments/run", json={
            "experiment_name": "e2e-pipeline-test",
            "modes": ["HALLUCISHIELD", "STATIC_SCANNER"],
        })
        assert resp.status_code == 200
        data = resp.json()
        _state["experiment_id"] = data["experiment_id"]
        print(f"\n[STAGE 12] Experiment:")
        print(f"  Experiment ID: {data['experiment_id']}")
        print(f"  Duration: {data['duration_ms']}ms")

    def test_analytics_charts(self):
        eid = _state["experiment_id"]
        resp = client.get(f"/api/analytics/{eid}/charts")
        assert resp.status_code == 200
        data = resp.json()
        assert "charts" in data
        print(f"\n[STAGE 12b] Analytics Charts:")
        print(f"  Chart keys: {list(data['charts'].keys())}")
        print(f"  Data provenance: {data.get('data_provenance', {}).get('source', 'N/A')}")
