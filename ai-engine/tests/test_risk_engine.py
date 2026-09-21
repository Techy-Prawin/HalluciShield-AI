"""
Risk Assessment Engine Test Suite for HalluciShield AI.

Tests deterministic risk scoring for:
- Category risk calculations
- Overall risk aggregation
- Risk level determination
- Recommendation generation
- API endpoint integration
"""

import os
import shutil
import tempfile
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.agents.risk_engine import RiskEngine, RiskScoringConfig
from app.agents.models import (
    HallucinationFinding,
    SecurityFinding,
    DependencyFinding,
    DetectionResponse,
    SecurityAnalysisResponse,
    DependencyAnalysisResponse,
    RiskAssessment,
    RiskLevel,
    VerificationStatus,
    FindingType,
    VerificationEvidence,
    VulnerabilitySeverity,
    VulnerabilityType,
    DependencySeverity,
    DependencyFindingType,
    DependencyType,
)

client = TestClient(app)


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def risk_engine():
    """Create a fresh RiskEngine instance."""
    return RiskEngine()


@pytest.fixture
def config():
    """Create test configuration."""
    return RiskScoringConfig()


def create_hallucination_finding(
    finding_id: str = "hall-001",
    severity: str = "HIGH",
    confidence: float = 0.85,
    file: str = "app.py",
    line: int = 10,
) -> HallucinationFinding:
    """Helper to create hallucination findings."""
    return HallucinationFinding(
        finding_id=finding_id,
        type=FindingType.HALLUCINATED_PACKAGE,
        file=file,
        line=line,
        evidence=VerificationEvidence(
            symbol_name="fake-package",
            check_type="REGISTRY_VERIFICATION",
            registry="npm",
            registry_status="404_NOT_FOUND",
            facts=["Package not found in npm registry"],
        ),
        explanation=f"Detected hallucinated package at {file}:{line}",
        severity=severity,
        confidence=confidence,
        verification_status=VerificationStatus.CONFIRMED,
        verification_method="DETERMINISTIC_REGISTRY_CHECK",
    )


def create_security_finding(
    finding_id: str = "sec-001",
    severity: VulnerabilitySeverity = VulnerabilitySeverity.HIGH,
    confidence: float = 0.92,
    file: str = "db.py",
    line: int = 25,
) -> SecurityFinding:
    """Helper to create security findings."""
    return SecurityFinding(
        finding_id=finding_id,
        type=VulnerabilityType.SQL_INJECTION,
        severity=severity,
        cwe="CWE-89",
        file=file,
        line=line,
        evidence="Query string concatenation detected",
        description="SQL Injection vulnerability found",
        scanner="semgrep",
        confidence=confidence,
    )


def create_dependency_finding(
    finding_id: str = "dep-001",
    severity: DependencySeverity = DependencySeverity.MEDIUM,
    package_name: str = "test-package",
    file: str = "package.json",
    line: int = 5,
) -> DependencyFinding:
    """Helper to create dependency findings."""
    return DependencyFinding(
        finding_id=finding_id,
        type=DependencyFindingType.SUSPICIOUS_DEPENDENCY,
        severity=severity,
        package_name=package_name,
        ecosystem=DependencyType.NPM,
        file=file,
        line=line,
        evidence=f"Package {package_name} has suspicious characteristics",
        description=f"Suspicious dependency: {package_name}",
        confidence=0.75,
    )


def create_detection_response(
    findings_count: int = 2,
    severity_distribution: dict = None,
) -> DetectionResponse:
    """Helper to create hallucination detection response."""
    if severity_distribution is None:
        severity_distribution = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0}
    
    findings = []
    idx = 0
    for severity, count in severity_distribution.items():
        for _ in range(count):
            findings.append(create_hallucination_finding(
                finding_id=f"hall-{idx:03d}",
                severity=severity,
            ))
            idx += 1
    
    return DetectionResponse(
        repository_id="test-repo",
        total_findings=len(findings),
        confirmed_findings_count=1,
        likely_findings_count=1,
        suspicious_findings_count=0,
        findings=findings,
        analysis_duration_ms=150,
    )


def create_security_response(
    severity_distribution: dict = None,
) -> SecurityAnalysisResponse:
    """Helper to create security analysis response."""
    if severity_distribution is None:
        severity_distribution = {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 1}
    
    findings = []
    idx = 0
    for severity_str, count in severity_distribution.items():
        severity = VulnerabilitySeverity(severity_str)
        for _ in range(count):
            findings.append(create_security_finding(
                finding_id=f"sec-{idx:03d}",
                severity=severity,
            ))
            idx += 1
    
    return SecurityAnalysisResponse(
        repository_id="test-repo",
        total_vulnerabilities=len(findings),
        critical_count=severity_distribution.get("CRITICAL", 0),
        high_count=severity_distribution.get("HIGH", 0),
        medium_count=severity_distribution.get("MEDIUM", 0),
        low_count=severity_distribution.get("LOW", 0),
        findings=findings,
        scan_duration_ms=200,
    )


def create_dependency_response(
    severity_distribution: dict = None,
) -> DependencyAnalysisResponse:
    """Helper to create dependency analysis response."""
    if severity_distribution is None:
        severity_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 2, "LOW": 1}
    
    findings = []
    idx = 0
    for severity_str, count in severity_distribution.items():
        severity = DependencySeverity(severity_str)
        for _ in range(count):
            findings.append(create_dependency_finding(
                finding_id=f"dep-{idx:03d}",
                severity=severity,
            ))
            idx += 1
    
    return DependencyAnalysisResponse(
        repository_id="test-repo",
        total_findings=len(findings),
        critical_count=severity_distribution.get("CRITICAL", 0),
        high_count=severity_distribution.get("HIGH", 0),
        medium_count=severity_distribution.get("MEDIUM", 0),
        low_count=severity_distribution.get("LOW", 0),
        findings=findings,
        dependencies_scanned=25,
        analysis_duration_ms=100,
    )


# ============================================================
# Test Category Risk Calculation
# ============================================================

class TestCategoryRiskCalculation:
    """Tests for individual category risk score calculation."""
    
    def test_empty_findings_return_zero_score(self, risk_engine):
        """Empty findings should return zero risk score."""
        result = risk_engine.calculate_category_risk("hallucination", [])
        assert result.risk_score == 0.0
        assert result.total_findings == 0
        assert result.top_issues == []
    
    def test_critical_findings_high_score(self, risk_engine):
        """Critical findings should produce high risk scores."""
        findings = [
            create_hallucination_finding(severity="CRITICAL"),
            create_hallucination_finding(severity="CRITICAL"),
        ]
        result = risk_engine.calculate_category_risk("hallucination", findings)
        # 2 * 25 = 50
        assert result.risk_score == 50.0
        assert result.critical_count == 2
    
    def test_high_findings_medium_score(self, risk_engine):
        """High findings should produce medium risk scores."""
        findings = [
            create_hallucination_finding(severity="HIGH"),
            create_hallucination_finding(severity="HIGH"),
            create_hallucination_finding(severity="HIGH"),
        ]
        result = risk_engine.calculate_category_risk("hallucination", findings)
        # 3 * 15 = 45
        assert result.risk_score == 45.0
        assert result.high_count == 3
    
    def test_medium_findings_low_score(self, risk_engine):
        """Medium findings should produce lower risk scores."""
        findings = [
            create_hallucination_finding(severity="MEDIUM"),
            create_hallucination_finding(severity="MEDIUM"),
        ]
        result = risk_engine.calculate_category_risk("hallucination", findings)
        # 2 * 8 = 16
        assert result.risk_score == 16.0
        assert result.medium_count == 2
    
    def test_low_findings_minimal_score(self, risk_engine):
        """Low findings should produce minimal risk scores."""
        findings = [
            create_hallucination_finding(severity="LOW"),
            create_hallucination_finding(severity="LOW"),
            create_hallucination_finding(severity="LOW"),
        ]
        result = risk_engine.calculate_category_risk("hallucination", findings)
        # 3 * 3 = 9
        assert result.risk_score == 9.0
        assert result.low_count == 3
    
    def test_mixed_severities(self, risk_engine):
        """Mixed severity findings should calculate correctly."""
        findings = [
            create_hallucination_finding(severity="CRITICAL"),  # 25
            create_hallucination_finding(severity="HIGH"),      # 15
            create_hallucination_finding(severity="MEDIUM"),    # 8
            create_hallucination_finding(severity="LOW"),       # 3
        ]
        result = risk_engine.calculate_category_risk("hallucination", findings)
        # 25 + 15 + 8 + 3 = 51
        assert result.risk_score == 51.0
        assert result.total_findings == 4
    
    def test_score_capped_at_100(self, risk_engine):
        """Risk score should be capped at 100."""
        # Create many critical findings to exceed 100
        findings = [
            create_hallucination_finding(severity="CRITICAL")
            for _ in range(5)  # 5 * 25 = 125, should cap at 100
        ]
        result = risk_engine.calculate_category_risk("hallucination", findings)
        assert result.risk_score == 100.0
    
    def test_top_issues_sorted_by_severity(self, risk_engine):
        """Top issues should be sorted by severity then confidence."""
        findings = [
            create_hallucination_finding(finding_id="low-1", severity="LOW", confidence=0.9),
            create_hallucination_finding(finding_id="crit-1", severity="CRITICAL", confidence=0.8),
            create_hallucination_finding(finding_id="high-1", severity="HIGH", confidence=0.85),
        ]
        result = risk_engine.calculate_category_risk("hallucination", findings)
        
        # Top issues should be limited to MAX_TOP_ISSUES (5)
        assert len(result.top_issues) <= 5
        
        # First should be CRITICAL
        assert result.top_issues[0]["severity"] == "CRITICAL"
        assert result.top_issues[0]["finding_id"] == "crit-1"


# ============================================================
# Test Overall Risk Calculation
# ============================================================

class TestOverallRiskCalculation:
    """Tests for overall risk score calculation."""
    
    def test_zero_risk_all_categories(self, risk_engine):
        """Zero risk in all categories should give zero overall."""
        hall_risk = risk_engine.calculate_category_risk("hallucination", [])
        sec_risk = risk_engine.calculate_category_risk("security", [])
        dep_risk = risk_engine.calculate_category_risk("dependency", [])
        
        score, level, factors = risk_engine.calculate_overall_risk(
            hall_risk, sec_risk, dep_risk
        )
        
        assert score == 0.0
        assert level == RiskLevel.INFO
    
    def test_weighted_average_calculation(self, risk_engine):
        """Overall score should be weighted average of categories."""
        # Create category risks with known scores
        from app.agents.models import CategoryRisk
        
        hall_risk = CategoryRisk(
            category="hallucination",
            risk_score=50.0,  # 50 * 0.40 = 20
            total_findings=2,
        )
        sec_risk = CategoryRisk(
            category="security",
            risk_score=60.0,  # 60 * 0.35 = 21
            total_findings=3,
        )
        dep_risk = CategoryRisk(
            category="dependency",
            risk_score=40.0,  # 40 * 0.25 = 10
            total_findings=2,
        )
        
        score, level, factors = risk_engine.calculate_overall_risk(
            hall_risk, sec_risk, dep_risk
        )
        
        # 20 + 21 + 10 = 51
        assert score == 51.0
        assert level == RiskLevel.MEDIUM
    
    def test_critical_overall_level(self, risk_engine):
        """High scores should result in CRITICAL level."""
        from app.agents.models import CategoryRisk
        
        hall_risk = CategoryRisk(category="hallucination", risk_score=100.0, total_findings=10)
        sec_risk = CategoryRisk(category="security", risk_score=100.0, total_findings=10)
        dep_risk = CategoryRisk(category="dependency", risk_score=100.0, total_findings=10)
        
        score, level, factors = risk_engine.calculate_overall_risk(
            hall_risk, sec_risk, dep_risk
        )
        
        assert score == 100.0
        assert level == RiskLevel.CRITICAL
    
    def test_risk_factors_identified(self, risk_engine):
        """Risk factors should be identified for high-risk categories."""
        from app.agents.models import CategoryRisk
        
        hall_risk = CategoryRisk(
            category="hallucination",
            risk_score=75.0,
            total_findings=5,
            critical_count=2,
        )
        sec_risk = CategoryRisk(category="security", risk_score=10.0, total_findings=1)
        dep_risk = CategoryRisk(category="dependency", risk_score=10.0, total_findings=1)
        
        score, level, factors = risk_engine.calculate_overall_risk(
            hall_risk, sec_risk, dep_risk
        )
        
        # Should identify high hallucination rate and critical findings
        assert len(factors) >= 1
        factor_categories = [f["category"] for f in factors]
        assert "hallucination" in factor_categories or "overall" in factor_categories


# ============================================================
# Test Risk Level Determination
# ============================================================

class TestRiskLevelDetermination:
    """Tests for risk level threshold determination."""
    
    def test_critical_level(self, risk_engine):
        """Score >= 80 should be CRITICAL."""
        assert risk_engine._determine_risk_level(80.0) == RiskLevel.CRITICAL
        assert risk_engine._determine_risk_level(95.0) == RiskLevel.CRITICAL
        assert risk_engine._determine_risk_level(100.0) == RiskLevel.CRITICAL
    
    def test_high_level(self, risk_engine):
        """Score >= 60 and < 80 should be HIGH."""
        assert risk_engine._determine_risk_level(60.0) == RiskLevel.HIGH
        assert risk_engine._determine_risk_level(75.0) == RiskLevel.HIGH
        assert risk_engine._determine_risk_level(79.9) == RiskLevel.HIGH
    
    def test_medium_level(self, risk_engine):
        """Score >= 40 and < 60 should be MEDIUM."""
        assert risk_engine._determine_risk_level(40.0) == RiskLevel.MEDIUM
        assert risk_engine._determine_risk_level(50.0) == RiskLevel.MEDIUM
        assert risk_engine._determine_risk_level(59.9) == RiskLevel.MEDIUM
    
    def test_low_level(self, risk_engine):
        """Score >= 20 and < 40 should be LOW."""
        assert risk_engine._determine_risk_level(20.0) == RiskLevel.LOW
        assert risk_engine._determine_risk_level(30.0) == RiskLevel.LOW
        assert risk_engine._determine_risk_level(39.9) == RiskLevel.LOW
    
    def test_info_level(self, risk_engine):
        """Score < 20 should be INFO."""
        assert risk_engine._determine_risk_level(0.0) == RiskLevel.INFO
        assert risk_engine._determine_risk_level(10.0) == RiskLevel.INFO
        assert risk_engine._determine_risk_level(19.9) == RiskLevel.INFO


# ============================================================
# Test Recommendation Generation
# ============================================================

class TestRecommendationGeneration:
    """Tests for recommendation generation logic."""
    
    def test_critical_hallucination_recommendation(self, risk_engine):
        """Critical hallucinations should generate urgent recommendation."""
        from app.agents.models import CategoryRisk
        
        hall_risk = CategoryRisk(
            category="hallucination",
            risk_score=50.0,
            total_findings=2,
            critical_count=2,
        )
        sec_risk = CategoryRisk(category="security", risk_score=0.0, total_findings=0)
        dep_risk = CategoryRisk(category="dependency", risk_score=0.0, total_findings=0)
        
        recommendations = risk_engine.generate_recommendations(
            hall_risk, sec_risk, dep_risk, RiskLevel.HIGH
        )
        
        urgent_recs = [r for r in recommendations if "URGENT" in r]
        assert len(urgent_recs) >= 1
        assert "hallucinated packages" in urgent_recs[0].lower()
    
    def test_critical_security_recommendation(self, risk_engine):
        """Critical security issues should generate urgent recommendation."""
        from app.agents.models import CategoryRisk
        
        hall_risk = CategoryRisk(category="hallucination", risk_score=0.0, total_findings=0)
        sec_risk = CategoryRisk(
            category="security",
            risk_score=75.0,
            total_findings=3,
            critical_count=3,
        )
        dep_risk = CategoryRisk(category="dependency", risk_score=0.0, total_findings=0)
        
        recommendations = risk_engine.generate_recommendations(
            hall_risk, sec_risk, dep_risk, RiskLevel.CRITICAL
        )
        
        urgent_recs = [r for r in recommendations if "URGENT" in r]
        assert len(urgent_recs) >= 1
        assert "vulnerabilities" in urgent_recs[0].lower()
    
    def test_critical_overall_recommendation(self, risk_engine):
        """CRITICAL overall level should generate deployment block recommendation."""
        from app.agents.models import CategoryRisk
        
        hall_risk = CategoryRisk(category="hallucination", risk_score=50.0, total_findings=2)
        sec_risk = CategoryRisk(category="security", risk_score=50.0, total_findings=2)
        dep_risk = CategoryRisk(category="dependency", risk_score=50.0, total_findings=2)
        
        recommendations = risk_engine.generate_recommendations(
            hall_risk, sec_risk, dep_risk, RiskLevel.CRITICAL
        )
        
        block_recs = [r for r in recommendations if "blocking deployment" in r.lower()]
        assert len(block_recs) >= 1
    
    def test_no_findings_generates_positive_recommendation(self, risk_engine):
        """No findings should generate positive recommendation."""
        from app.agents.models import CategoryRisk
        
        hall_risk = CategoryRisk(category="hallucination", risk_score=0.0, total_findings=0)
        sec_risk = CategoryRisk(category="security", risk_score=0.0, total_findings=0)
        dep_risk = CategoryRisk(category="dependency", risk_score=0.0, total_findings=0)
        
        recommendations = risk_engine.generate_recommendations(
            hall_risk, sec_risk, dep_risk, RiskLevel.INFO
        )
        
        assert len(recommendations) == 1
        assert "no critical issues" in recommendations[0].lower()


# ============================================================
# Test Full Risk Assessment
# ============================================================

class TestFullRiskAssessment:
    """Tests for the complete risk assessment pipeline."""
    
    def test_assess_risk_with_empty_responses(self, risk_engine):
        """Empty responses should produce zero-risk assessment."""
        hall_response = create_detection_response(findings_count=0)
        hall_response.findings = []
        hall_response.total_findings = 0
        
        sec_response = create_security_response()
        sec_response.findings = []
        sec_response.total_vulnerabilities = 0
        
        dep_response = create_dependency_response()
        dep_response.findings = []
        dep_response.total_findings = 0
        
        assessment = risk_engine.assess_risk(
            "test-repo", hall_response, sec_response, dep_response
        )
        
        assert assessment.overall_risk_score == 0.0
        assert assessment.overall_risk_level == RiskLevel.INFO
        assert assessment.total_findings == 0
        assert assessment.critical_findings == 0
    
    def test_assess_risk_with_mixed_findings(self, risk_engine):
        """Mixed findings should calculate correctly."""
        hall_response = create_detection_response(
            severity_distribution={"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
        )
        sec_response = create_security_response(
            severity_distribution={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 1}
        )
        dep_response = create_dependency_response(
            severity_distribution={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 2}
        )
        
        assessment = risk_engine.assess_risk(
            "test-repo", hall_response, sec_response, dep_response
        )
        
        # Verify totals
        assert assessment.total_findings == 11  # 4 + 4 + 3
        assert assessment.critical_findings == 1
        assert assessment.high_findings == 3
        assert assessment.medium_findings == 4
        assert assessment.low_findings == 3
        
        # Verify category risks
        assert assessment.hallucination_risk.total_findings == 4
        assert assessment.security_risk.total_findings == 4
        assert assessment.dependency_risk.total_findings == 3
        
        # Verify timestamp is ISO format
        datetime.fromisoformat(assessment.timestamp.replace('Z', '+00:00'))
        
        # Verify recommendations exist
        assert len(assessment.recommendations) > 0
    
    def test_assess_risk_deterministic(self, risk_engine):
        """Same inputs should produce identical outputs."""
        hall_response = create_detection_response(
            severity_distribution={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0}
        )
        sec_response = create_security_response(
            severity_distribution={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0}
        )
        dep_response = create_dependency_response(
            severity_distribution={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0}
        )
        
        assessment1 = risk_engine.assess_risk(
            "test-repo", hall_response, sec_response, dep_response
        )
        assessment2 = risk_engine.assess_risk(
            "test-repo", hall_response, sec_response, dep_response
        )
        
        # Scores should be identical
        assert assessment1.overall_risk_score == assessment2.overall_risk_score
        assert assessment1.overall_risk_level == assessment2.overall_risk_level
        assert assessment1.hallucination_risk.risk_score == assessment2.hallucination_risk.risk_score
        assert assessment1.security_risk.risk_score == assessment2.security_risk.risk_score
        assert assessment1.dependency_risk.risk_score == assessment2.dependency_risk.risk_score


# ============================================================
# Test API Endpoint
# ============================================================

class TestRiskAPIEndpoint:
    """Tests for the risk assessment API endpoint."""
    
    @patch("app.api.risk.dependency_agent")
    @patch("app.api.risk.security_agent")
    @patch("app.api.risk.hallucination_agent")
    def test_risk_get_endpoint_with_mock(self, mock_hall, mock_sec, mock_dep):
        """GET risk endpoint should return valid risk assessment with mocked agents."""
        mock_hall.detect_hallucinations.return_value = create_detection_response(
            severity_distribution={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0}
        )
        mock_sec.analyze_security.return_value = create_security_response(
            severity_distribution={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0}
        )
        mock_dep.analyze_dependencies.return_value = create_dependency_response(
            severity_distribution={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 1}
        )
        
        response = client.get(
            "/api/v1/risk/repositories/test-repo/risk",
            params={"workspace_path": "/tmp/test"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["repository_id"] == "test-repo"
        assert "risk_assessment" in data
        assert "overall_risk_score" in data["risk_assessment"]
        assert "hallucination_risk" in data["risk_assessment"]
        assert "security_risk" in data["risk_assessment"]
        assert "dependency_risk" in data["risk_assessment"]
        assert "recommendations" in data["risk_assessment"]
    
    @patch("app.api.risk.dependency_agent")
    @patch("app.api.risk.security_agent")
    @patch("app.api.risk.hallucination_agent")
    def test_risk_post_endpoint_with_mock(self, mock_hall, mock_sec, mock_dep):
        """POST risk endpoint should return valid risk assessment with mocked agents."""
        mock_hall.detect_hallucinations.return_value = create_detection_response(
            severity_distribution={"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        )
        mock_sec.analyze_security.return_value = create_security_response(
            severity_distribution={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        )
        mock_dep.analyze_dependencies.return_value = create_dependency_response(
            severity_distribution={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        )
        
        response = client.post(
            "/api/v1/risk/assess",
            json={
                "repository_id": "test-repo-2",
                "workspace_path": "/tmp/test"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["repository_id"] == "test-repo-2"
        ra = data["risk_assessment"]
        assert ra["critical_findings"] == 1
        assert ra["total_findings"] == 1
        assert ra["overall_risk_level"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    
    @patch("app.api.risk.hallucination_agent")
    def test_risk_get_handles_agent_error(self, mock_hall):
        """GET risk endpoint should return 500 on agent error."""
        mock_hall.detect_hallucinations.side_effect = RuntimeError("Scan failed")
        
        response = client.get(
            "/api/v1/risk/repositories/test-repo/risk",
            params={"workspace_path": "/tmp/test"}
        )
        
        assert response.status_code == 500
        assert response.json()["detail"] == "Internal server error"
    
    @patch("app.api.risk.dependency_agent")
    @patch("app.api.risk.security_agent")
    @patch("app.api.risk.hallucination_agent")
    def test_risk_score_deterministic_via_api(self, mock_hall, mock_sec, mock_dep):
        """Same inputs via API should produce same risk scores."""
        mock_hall.detect_hallucinations.return_value = create_detection_response(
            severity_distribution={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0}
        )
        mock_sec.analyze_security.return_value = create_security_response(
            severity_distribution={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0}
        )
        mock_dep.analyze_dependencies.return_value = create_dependency_response(
            severity_distribution={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0}
        )
        
        resp1 = client.get(
            "/api/v1/risk/repositories/test-repo/risk",
            params={"workspace_path": "/tmp/test"}
        )
        resp2 = client.get(
            "/api/v1/risk/repositories/test-repo/risk",
            params={"workspace_path": "/tmp/test"}
        )
        
        score1 = resp1.json()["risk_assessment"]["overall_risk_score"]
        score2 = resp2.json()["risk_assessment"]["overall_risk_score"]
        assert score1 == score2
    
    @patch("app.api.risk.dependency_agent")
    @patch("app.api.risk.security_agent")
    @patch("app.api.risk.hallucination_agent")
    def test_risk_response_structure(self, mock_hall, mock_sec, mock_dep):
        """Risk response should have all required fields."""
        mock_hall.detect_hallucinations.return_value = create_detection_response()
        mock_sec.analyze_security.return_value = create_security_response()
        mock_dep.analyze_dependencies.return_value = create_dependency_response()
        
        response = client.get(
            "/api/v1/risk/repositories/test-repo/risk",
            params={"workspace_path": "/tmp/test"}
        )
        
        data = response.json()
        ra = data["risk_assessment"]
        
        # Verify top-level fields
        assert "repository_id" in data
        assert "risk_assessment" in data
        assert "analysis_duration_ms" in data
        
        # Verify risk assessment fields
        assert "timestamp" in ra
        assert "overall_risk_score" in ra
        assert "overall_risk_level" in ra
        assert "total_findings" in ra
        assert "critical_findings" in ra
        assert "high_findings" in ra
        assert "medium_findings" in ra
        assert "low_findings" in ra
        assert "hallucination_risk" in ra
        assert "security_risk" in ra
        assert "dependency_risk" in ra
        assert "risk_factors" in ra
        assert "recommendations" in ra
        
        # Verify category risk structure
        for cat_key in ["hallucination_risk", "security_risk", "dependency_risk"]:
            cat = ra[cat_key]
            assert "category" in cat
            assert "risk_score" in cat
            assert "total_findings" in cat
            assert "critical_count" in cat
            assert "high_count" in cat
            assert "medium_count" in cat
            assert "low_count" in cat
            assert "top_issues" in cat

    def test_dashboard_endpoint_serves_html(self):
        """Dashboard endpoint should serve HTML."""
        response = client.get("/api/v1/dashboard/risk")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "HalluciShield" in response.text
    
    def test_root_includes_risk_endpoint(self):
        """Root endpoint should list risk assessment endpoint."""
        response = client.get("/")
        data = response.json()
        assert "riskAssessmentEndpoint" in data
        assert "dashboardEndpoint" in data


# ============================================================
# Test Configuration
# ============================================================

class TestRiskScoringConfig:
    """Tests for risk scoring configuration."""
    
    def test_severity_weights_sum(self, config):
        """Severity weights should be defined correctly."""
        assert config.SEVERITY_WEIGHTS["CRITICAL"] == 25.0
        assert config.SEVERITY_WEIGHTS["HIGH"] == 15.0
        assert config.SEVERITY_WEIGHTS["MEDIUM"] == 8.0
        assert config.SEVERITY_WEIGHTS["LOW"] == 3.0
    
    def test_category_weights_sum_to_one(self, config):
        """Category weights should sum to 1.0."""
        total = sum(config.CATEGORY_WEIGHTS.values())
        assert abs(total - 1.0) < 0.001
    
    def test_risk_thresholds_ordered(self, config):
        """Risk thresholds should be properly ordered."""
        thresholds = list(config.RISK_THRESHOLDS.values())
        # Should be in descending order
        for i in range(len(thresholds) - 1):
            assert thresholds[i] > thresholds[i + 1]
    
    def test_max_category_score(self, config):
        """Max category score should be 100."""
        assert config.MAX_CATEGORY_SCORE == 100.0


# ============================================================
# Test Edge Cases
# ============================================================

class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""
    
    def test_single_critical_finding(self, risk_engine):
        """Single critical finding should produce expected score."""
        findings = [create_hallucination_finding(severity="CRITICAL")]
        result = risk_engine.calculate_category_risk("hallucination", findings)
        assert result.risk_score == 25.0
    
    def test_boundary_risk_levels(self, risk_engine):
        """Boundary values should map to correct risk levels."""
        # Exactly at threshold
        assert risk_engine._determine_risk_level(80.0) == RiskLevel.CRITICAL
        assert risk_engine._determine_risk_level(60.0) == RiskLevel.HIGH
        assert risk_engine._determine_risk_level(40.0) == RiskLevel.MEDIUM
        assert risk_engine._determine_risk_level(20.0) == RiskLevel.LOW
        assert risk_engine._determine_risk_level(0.0) == RiskLevel.INFO
    
    def test_all_severities_in_single_category(self, risk_engine):
        """All severity levels in one category should calculate correctly."""
        findings = [
            create_hallucination_finding(severity="CRITICAL"),  # 25
            create_hallucination_finding(severity="HIGH"),      # 15
            create_hallucination_finding(severity="MEDIUM"),    # 8
            create_hallucination_finding(severity="LOW"),       # 3
        ]
        result = risk_engine.calculate_category_risk("hallucination", findings)
        assert result.risk_score == 51.0
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.medium_count == 1
        assert result.low_count == 1
