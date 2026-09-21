"""
Comprehensive test suite for Human-in-the-Loop Patch Approval Service.

Tests: Review assembly, approval recording, rejection recording,
diff generation, approval history, status checks, API endpoints,
edge cases, and mandatory developer approval.
"""

import pytest
from fastapi.testclient import TestClient

from app.agents.patch_approval import PatchApprovalService, _generate_diff
from app.agents.models import (
    ApprovalDecision,
    ApprovePatchRequest,
    PatchApprovalRecord,
    PatchApprovalResponse,
    PatchCandidate,
    PatchReviewResponse,
    RejectPatchRequest,
    CompilationScore,
    FunctionalBehaviorScore,
    PatchValidationResult,
    PerformanceImpactScore,
    RegressionScore,
    SecurityValidationScore,
    UnitTestScore,
    ValidationStatus,
)
from app.main import app


@pytest.fixture
def service():
    return PatchApprovalService()


@pytest.fixture
def sample_candidate():
    return PatchCandidate(
        patch_id="patch-001",
        modified_code='def query(user_input):\n    cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))\n    return cursor.fetchall()',
        explanation="Use parameterized query to prevent SQL injection",
        security_strategy="parameterized_query",
        expected_effect="Prevents SQL injection by using parameterized queries",
    )


@pytest.fixture
def perfect_validation():
    return PatchValidationResult(
        patch_id="patch-001", vulnerability_id="vuln-001",
        compilation_score=CompilationScore(score=1.0, success=True, language="python"),
        unit_test_score=UnitTestScore(score=1.0, total_tests=20, passed=20, failed=0),
        regression_score=RegressionScore(score=1.0, total_tests=15, passed=15, failed=0),
        security_score=SecurityValidationScore(score=1.0, vulnerabilities_found=0),
        functional_score=FunctionalBehaviorScore(score=1.0, tests_run=20, behavior_preserved=True),
        performance_score=PerformanceImpactScore(score=1.0, within_acceptable_range=True),
        validation_status=ValidationStatus.PASS,
    )


@pytest.fixture
def failing_validation():
    return PatchValidationResult(
        patch_id="patch-002", vulnerability_id="vuln-001",
        compilation_score=CompilationScore(score=0.0, success=False, error="syntax error"),
        unit_test_score=UnitTestScore(score=0.1, total_tests=10, passed=1, failed=9),
        regression_score=RegressionScore(score=0.2, total_tests=10, passed=2, failed=8, regressions_found=8),
        security_score=SecurityValidationScore(score=0.3, vulnerabilities_found=3, critical=1, high=1, medium=1),
        functional_score=FunctionalBehaviorScore(score=0.2, tests_run=10, behavior_preserved=False),
        performance_score=PerformanceImpactScore(score=0.3, within_acceptable_range=False, time_regression_pct=120.0),
        validation_status=ValidationStatus.FAIL,
    )


@pytest.fixture
def client():
    return TestClient(app)


# ============================================================
# Diff Generation Tests
# ============================================================

class TestDiffGeneration:
    def test_diff_basic(self):
        original = "line1\nline2\nline3\n"
        patched = "line1\nmodified\nline3\n"
        diff = _generate_diff(original, patched)
        assert "-line2" in diff
        assert "+modified" in diff
        assert "@@" in diff

    def test_diff_no_changes(self):
        code = "line1\nline2\nline3\n"
        diff = _generate_diff(code, code)
        assert diff == ""

    def test_diff_empty_files(self):
        diff = _generate_diff("", "new content")
        assert "+new content" in diff

    def test_diff_additions(self):
        original = "line1\n"
        patched = "line1\nline2\nline3\n"
        diff = _generate_diff(original, patched)
        assert "+line2" in diff
        assert "+line3" in diff

    def test_diff_deletions(self):
        original = "line1\nline2\nline3\n"
        patched = "line1\n"
        diff = _generate_diff(original, patched)
        assert "-line2" in diff
        assert "-line3" in diff

    def test_diff_completely_different(self):
        original = "foo\nbar\n"
        patched = "baz\nqux\n"
        diff = _generate_diff(original, patched)
        assert "-foo" in diff
        assert "+baz" in diff

    def test_diff_single_line(self):
        original = "old"
        patched = "new"
        diff = _generate_diff(original, patched)
        assert "-old" in diff
        assert "+new" in diff

    def test_diff_multiline_changes(self):
        original = "a\nb\nc\nd\ne\n"
        patched = "a\nX\nc\nd\nY\n"
        diff = _generate_diff(original, patched)
        assert "-b" in diff
        assert "+X" in diff
        assert "-e" in diff
        assert "+Y" in diff


# ============================================================
# Review Assembly Tests
# ============================================================

class TestReviewAssembly:
    def test_build_review_basic(self, service, sample_candidate):
        review = service.build_review(
            vulnerability_id="vuln-001",
            patch_id="patch-001",
            patch_candidate=sample_candidate,
            original_code='def query(user_input):\n    cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")\n    return cursor.fetchall()',
        )
        assert review.vulnerability_id == "vuln-001"
        assert review.patch_id == "patch-001"
        assert review.original_code != ""
        assert review.patched_code != ""
        assert review.diff != ""
        assert review.created_at != ""

    def test_build_review_includes_vulnerability_info(self, service, sample_candidate):
        review = service.build_review(
            vulnerability_id="vuln-001",
            patch_id="patch-001",
            patch_candidate=sample_candidate,
            original_code="old code",
            vulnerability_type="SQL_INJECTION",
            vulnerability_description="SQL injection via f-string",
            vulnerability_severity="CRITICAL",
        )
        assert review.vulnerability_type == "SQL_INJECTION"
        assert review.vulnerability_description == "SQL injection via f-string"
        assert review.vulnerability_severity == "CRITICAL"

    def test_build_review_with_validation(self, service, sample_candidate, perfect_validation):
        review = service.build_review(
            vulnerability_id="vuln-001",
            patch_id="patch-001",
            patch_candidate=sample_candidate,
            original_code="old code",
            validation_result=perfect_validation,
        )
        assert review.validation_results is not None
        assert review.confidence_score > 0
        assert review.explanation is not None

    def test_build_review_without_candidate(self, service):
        review = service.build_review(
            vulnerability_id="vuln-001",
            patch_id="patch-001",
            original_code="old code",
        )
        assert review.patched_code == ""
        assert review.diff == ""

    def test_build_review_no_original_code(self, service, sample_candidate):
        review = service.build_review(
            vulnerability_id="vuln-001",
            patch_id="patch-001",
            patch_candidate=sample_candidate,
        )
        assert review.diff == ""


# ============================================================
# Approval Recording Tests
# ============================================================

class TestApprovalRecording:
    def test_approve_patch(self, service):
        response = service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001",
            patch_id="patch-001",
            vulnerability_id="vuln-001",
            confidence_score=92.5,
            vulnerability_type="SQL_INJECTION",
            patch_strategy="parameterized_query",
        ))
        assert response.decision == ApprovalDecision.APPROVED
        assert response.approval_record.developer_id == "dev-001"
        assert response.approval_record.confidence_score == 92.5
        assert response.approval_record.vulnerability_type == "SQL_INJECTION"
        assert response.approval_record.patch_strategy == "parameterized_query"
        assert response.approval_record.approved_at is not None
        assert response.approval_record.rejected_at is None
        assert "approved" in response.message.lower()

    def test_approve_records_timestamp(self, service):
        response = service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001",
            patch_id="patch-001",
            vulnerability_id="vuln-001",
            confidence_score=85.0,
        ))
        assert response.approval_record.approved_at is not None
        assert response.approval_record.created_at is not None

    def test_approve_records_confidence(self, service):
        response = service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001",
            patch_id="patch-001",
            vulnerability_id="vuln-001",
            confidence_score=67.3,
            vulnerability_type="XSS",
            patch_strategy="output_encoding",
        ))
        assert response.approval_record.confidence_score == 67.3
        assert response.approval_record.vulnerability_type == "XSS"
        assert response.approval_record.patch_strategy == "output_encoding"

    def test_approve_stored_in_history(self, service):
        service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001",
            patch_id="patch-001",
            vulnerability_id="vuln-001",
            confidence_score=90.0,
        ))
        history = service.get_approval_history(vulnerability_id="vuln-001")
        assert len(history) == 1
        assert history[0].decision == ApprovalDecision.APPROVED


# ============================================================
# Rejection Recording Tests
# ============================================================

class TestRejectionRecording:
    def test_reject_patch(self, service):
        response = service.reject_patch(RejectPatchRequest(
            developer_id="dev-001",
            patch_id="patch-001",
            vulnerability_id="vuln-001",
            reason="Does not handle edge cases",
        ))
        assert response.decision == ApprovalDecision.REJECTED
        assert response.approval_record.developer_id == "dev-001"
        assert response.approval_record.rejection_reason == "Does not handle edge cases"
        assert response.approval_record.rejected_at is not None
        assert response.approval_record.approved_at is None
        assert "rejected" in response.message.lower()

    def test_reject_without_reason(self, service):
        response = service.reject_patch(RejectPatchRequest(
            developer_id="dev-001",
            patch_id="patch-001",
            vulnerability_id="vuln-001",
        ))
        assert response.decision == ApprovalDecision.REJECTED
        assert response.approval_record.rejection_reason == ""

    def test_reject_records_timestamp(self, service):
        response = service.reject_patch(RejectPatchRequest(
            developer_id="dev-001",
            patch_id="patch-001",
            vulnerability_id="vuln-001",
            reason="Security concern",
        ))
        assert response.approval_record.rejected_at is not None
        assert response.approval_record.created_at is not None

    def test_reject_stored_in_history(self, service):
        service.reject_patch(RejectPatchRequest(
            developer_id="dev-001",
            patch_id="patch-001",
            vulnerability_id="vuln-001",
            reason="Not secure enough",
        ))
        history = service.get_approval_history(vulnerability_id="vuln-001")
        assert len(history) == 1
        assert history[0].decision == ApprovalDecision.REJECTED


# ============================================================
# Approval Status Tests
# ============================================================

class TestApprovalStatus:
    def test_status_before_decision(self, service):
        record = service.get_approval_status("vuln-001", "patch-001")
        assert record is None

    def test_status_after_approval(self, service):
        service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001",
            patch_id="patch-001",
            vulnerability_id="vuln-001",
            confidence_score=90.0,
        ))
        record = service.get_approval_status("vuln-001", "patch-001")
        assert record is not None
        assert record.decision == ApprovalDecision.APPROVED

    def test_status_after_rejection(self, service):
        service.reject_patch(RejectPatchRequest(
            developer_id="dev-001",
            patch_id="patch-001",
            vulnerability_id="vuln-001",
            reason="Bad approach",
        ))
        record = service.get_approval_status("vuln-001", "patch-001")
        assert record is not None
        assert record.decision == ApprovalDecision.REJECTED

    def test_is_patch_approved_true(self, service):
        service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001",
            patch_id="patch-001",
            vulnerability_id="vuln-001",
            confidence_score=90.0,
        ))
        assert service.is_patch_approved("vuln-001", "patch-001") is True

    def test_is_patch_approved_rejected(self, service):
        service.reject_patch(RejectPatchRequest(
            developer_id="dev-001",
            patch_id="patch-001",
            vulnerability_id="vuln-001",
        ))
        assert service.is_patch_approved("vuln-001", "patch-001") is False

    def test_is_patch_approved_unknown(self, service):
        assert service.is_patch_approved("vuln-001", "patch-001") is False


# ============================================================
# Approval History Tests
# ============================================================

class TestApprovalHistory:
    def test_empty_history(self, service):
        history = service.get_approval_history()
        assert history == []

    def test_history_multiple_records(self, service):
        service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001", patch_id="patch-001",
            vulnerability_id="vuln-001", confidence_score=90.0,
        ))
        service.reject_patch(RejectPatchRequest(
            developer_id="dev-002", patch_id="patch-002",
            vulnerability_id="vuln-001", reason="Not good",
        ))
        service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001", patch_id="patch-003",
            vulnerability_id="vuln-002", confidence_score=85.0,
        ))
        history = service.get_approval_history()
        assert len(history) == 3

    def test_history_filter_by_vulnerability(self, service):
        service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001", patch_id="patch-001",
            vulnerability_id="vuln-001", confidence_score=90.0,
        ))
        service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001", patch_id="patch-002",
            vulnerability_id="vuln-002", confidence_score=85.0,
        ))
        history = service.get_approval_history(vulnerability_id="vuln-001")
        assert len(history) == 1
        assert history[0].vulnerability_id == "vuln-001"

    def test_history_filter_by_developer(self, service):
        service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001", patch_id="patch-001",
            vulnerability_id="vuln-001", confidence_score=90.0,
        ))
        service.reject_patch(RejectPatchRequest(
            developer_id="dev-002", patch_id="patch-002",
            vulnerability_id="vuln-001", reason="Bad",
        ))
        history = service.get_approval_history(developer_id="dev-001")
        assert len(history) == 1
        assert history[0].developer_id == "dev-001"

    def test_history_combined_filters(self, service):
        service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001", patch_id="patch-001",
            vulnerability_id="vuln-001", confidence_score=90.0,
        ))
        service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001", patch_id="patch-002",
            vulnerability_id="vuln-002", confidence_score=85.0,
        ))
        service.reject_patch(RejectPatchRequest(
            developer_id="dev-002", patch_id="patch-003",
            vulnerability_id="vuln-001", reason="Bad",
        ))
        history = service.get_approval_history(
            vulnerability_id="vuln-001", developer_id="dev-001"
        )
        assert len(history) == 1
        assert history[0].patch_id == "patch-001"


# ============================================================
# Mandatory Developer Approval Tests
# ============================================================

class TestMandatoryDeveloperApproval:
    def test_approve_requires_developer_id(self, service):
        with pytest.raises(ValueError, match="developer_id is required"):
            service.approve_patch(ApprovePatchRequest(
                developer_id="",
                patch_id="patch-001",
                vulnerability_id="vuln-001",
                confidence_score=90.0,
            ))

    def test_reject_requires_developer_id(self, service):
        with pytest.raises(ValueError, match="developer_id is required"):
            service.reject_patch(RejectPatchRequest(
                developer_id="",
                patch_id="patch-001",
                vulnerability_id="vuln-001",
            ))

    def test_no_auto_deploy_on_approval(self, service):
        response = service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001",
            patch_id="patch-001",
            vulnerability_id="vuln-001",
            confidence_score=99.0,
        ))
        assert "deploy" not in response.message.lower() or "ready for deployment" in response.message.lower()
        assert response.decision == ApprovalDecision.APPROVED


# ============================================================
# Model Tests
# ============================================================

class TestApprovalModels:
    def test_approval_record_fields(self):
        record = PatchApprovalRecord(
            id="appr-001",
            vulnerability_id="vuln-001",
            patch_id="patch-001",
            decision=ApprovalDecision.APPROVED,
            developer_id="dev-001",
            confidence_score=90.0,
            vulnerability_type="SQL_INJECTION",
            patch_strategy="parameterized_query",
            approved_at="2025-01-01T00:00:00Z",
            created_at="2025-01-01T00:00:00Z",
        )
        assert record.id == "appr-001"
        assert record.decision == ApprovalDecision.APPROVED

    def test_approval_response_fields(self):
        record = PatchApprovalRecord(
            id="appr-001",
            vulnerability_id="vuln-001",
            patch_id="patch-001",
            decision=ApprovalDecision.APPROVED,
            developer_id="dev-001",
        )
        response = PatchApprovalResponse(
            vulnerability_id="vuln-001",
            patch_id="patch-001",
            decision=ApprovalDecision.APPROVED,
            approval_record=record,
            message="Approved",
        )
        assert response.status == "success"
        assert response.decision == ApprovalDecision.APPROVED

    def test_review_response_fields(self):
        review = PatchReviewResponse(
            vulnerability_id="vuln-001",
            patch_id="patch-001",
            original_code="old",
            patched_code="new",
            diff="-old\n+new",
            vulnerability_type="SQL_INJECTION",
            vulnerability_severity="CRITICAL",
        )
        assert review.vulnerability_id == "vuln-001"
        assert review.diff == "-old\n+new"

    def test_approval_decision_enum(self):
        assert ApprovalDecision.APPROVED == "APPROVED"
        assert ApprovalDecision.REJECTED == "REJECTED"
        assert ApprovalDecision.PENDING == "PENDING"


# ============================================================
# Multiple Patches for Same Vulnerability Tests
# ============================================================

class TestMultiplePatches:
    def test_approve_one_reject_others(self, service):
        service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001", patch_id="patch-001",
            vulnerability_id="vuln-001", confidence_score=90.0,
        ))
        service.reject_patch(RejectPatchRequest(
            developer_id="dev-001", patch_id="patch-002",
            vulnerability_id="vuln-001", reason="Worse approach",
        ))
        assert service.is_patch_approved("vuln-001", "patch-001") is True
        assert service.is_patch_approved("vuln-001", "patch-002") is False
        history = service.get_approval_history(vulnerability_id="vuln-001")
        assert len(history) == 2

    def test_overwrite_decision(self, service):
        service.reject_patch(RejectPatchRequest(
            developer_id="dev-001", patch_id="patch-001",
            vulnerability_id="vuln-001", reason="Initial rejection",
        ))
        service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001", patch_id="patch-001",
            vulnerability_id="vuln-001", confidence_score=85.0,
        ))
        record = service.get_approval_status("vuln-001", "patch-001")
        assert record.decision == ApprovalDecision.APPROVED


# ============================================================
# API Endpoint Tests
# ============================================================

class TestApprovalAPIEndpoints:
    def test_get_review_endpoint(self, client):
        response = client.get(
            "/api/v1/vulnerabilities/vuln-001/patches/patch-001/review",
            params={
                "original_code": "old code",
                "patched_code": "new code",
                "vulnerability_type": "SQL_INJECTION",
                "vulnerability_severity": "CRITICAL",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["vulnerability_id"] == "vuln-001"
        assert data["patch_id"] == "patch-001"
        assert data["original_code"] == "old code"
        assert data["patched_code"] == "new code"
        assert data["diff"] != ""

    def test_approve_endpoint(self, client):
        response = client.post(
            "/api/v1/vulnerabilities/vuln-001/patches/patch-001/approve",
            json={
                "developer_id": "dev-001",
                "patch_id": "patch-001",
                "vulnerability_id": "vuln-001",
                "confidence_score": 92.5,
                "vulnerability_type": "SQL_INJECTION",
                "patch_strategy": "parameterized_query",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "APPROVED"
        assert data["approval_record"]["developer_id"] == "dev-001"
        assert data["approval_record"]["confidence_score"] == 92.5
        assert "approved" in data["message"].lower()

    def test_reject_endpoint(self, client):
        response = client.post(
            "/api/v1/vulnerabilities/vuln-001/patches/patch-001/reject",
            json={
                "developer_id": "dev-001",
                "patch_id": "patch-001",
                "vulnerability_id": "vuln-001",
                "reason": "Does not handle edge cases",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "REJECTED"
        assert data["approval_record"]["rejection_reason"] == "Does not handle edge cases"

    def test_reject_endpoint_no_reason(self, client):
        response = client.post(
            "/api/v1/vulnerabilities/vuln-001/patches/patch-001/reject",
            json={
                "developer_id": "dev-001",
                "patch_id": "patch-001",
                "vulnerability_id": "vuln-001",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "REJECTED"
        assert data["approval_record"]["rejection_reason"] == ""

    def test_approval_status_endpoint(self, client):
        client.post(
            "/api/v1/vulnerabilities/vuln-001/patches/patch-001/approve",
            json={
                "developer_id": "dev-001",
                "patch_id": "patch-001",
                "vulnerability_id": "vuln-001",
                "confidence_score": 90.0,
            },
        )
        response = client.get(
            "/api/v1/vulnerabilities/vuln-001/patches/patch-001/approval-status",
        )
        assert response.status_code == 200
        data = response.json()
        assert data["record"] is not None
        assert data["record"]["decision"] == "APPROVED"

    def test_approval_status_no_decision(self, client):
        response = client.get(
            "/api/v1/vulnerabilities/vuln-001/patches/patch-unknown/approval-status",
        )
        assert response.status_code == 200
        data = response.json()
        assert data["record"] is None
        assert data["status"] == "no_decision"

    def test_get_approvals_for_vulnerability(self, client):
        client.post(
            "/api/v1/vulnerabilities/vuln-001/patches/patch-001/approve",
            json={
                "developer_id": "dev-001",
                "patch_id": "patch-001",
                "vulnerability_id": "vuln-001",
                "confidence_score": 90.0,
            },
        )
        client.post(
            "/api/v1/vulnerabilities/vuln-001/patches/patch-002/reject",
            json={
                "developer_id": "dev-002",
                "patch_id": "patch-002",
                "vulnerability_id": "vuln-001",
                "reason": "Bad",
            },
        )
        response = client.get("/api/v1/vulnerabilities/vuln-001/approvals")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 2

    def test_review_with_diff(self, client):
        response = client.get(
            "/api/v1/vulnerabilities/vuln-001/patches/patch-001/review",
            params={
                "original_code": "line1\nline2\n",
                "patched_code": "line1\nmodified\n",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "-line2" in data["diff"]
        assert "+modified" in data["diff"]


# ============================================================
# Edge Case Tests
# ============================================================

class TestEdgeCases:
    def test_approve_same_patch_twice(self, service):
        service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001", patch_id="patch-001",
            vulnerability_id="vuln-001", confidence_score=90.0,
        ))
        response = service.approve_patch(ApprovePatchRequest(
            developer_id="dev-002", patch_id="patch-001",
            vulnerability_id="vuln-001", confidence_score=85.0,
        ))
        record = service.get_approval_status("vuln-001", "patch-001")
        assert record.decision == ApprovalDecision.APPROVED
        assert record.developer_id == "dev-002"

    def test_approve_then_reject(self, service):
        service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001", patch_id="patch-001",
            vulnerability_id="vuln-001", confidence_score=90.0,
        ))
        service.reject_patch(RejectPatchRequest(
            developer_id="dev-002", patch_id="patch-001",
            vulnerability_id="vuln-001", reason="Changed mind",
        ))
        record = service.get_approval_status("vuln-001", "patch-001")
        assert record.decision == ApprovalDecision.REJECTED
        assert record.rejection_reason == "Changed mind"

    def test_different_vulnerabilities_independent(self, service):
        service.approve_patch(ApprovePatchRequest(
            developer_id="dev-001", patch_id="patch-001",
            vulnerability_id="vuln-001", confidence_score=90.0,
        ))
        service.reject_patch(RejectPatchRequest(
            developer_id="dev-001", patch_id="patch-001",
            vulnerability_id="vuln-002", reason="Different vuln",
        ))
        assert service.is_patch_approved("vuln-001", "patch-001") is True
        assert service.is_patch_approved("vuln-002", "patch-001") is False

    def test_review_with_empty_codes(self, service):
        review = service.build_review(
            vulnerability_id="vuln-001",
            patch_id="patch-001",
        )
        assert review.original_code == ""
        assert review.patched_code == ""
        assert review.diff == ""

    def test_review_with_only_original(self, service):
        review = service.build_review(
            vulnerability_id="vuln-001",
            patch_id="patch-001",
            original_code="old code",
        )
        assert review.original_code == "old code"
        assert review.patched_code == ""
        assert review.diff == ""
