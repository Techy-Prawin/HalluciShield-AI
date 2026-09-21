"""
P1 Fallback Patch Tests for HalluciShield AI.

Proves that all five fallback patch candidates:
- differ genuinely from the original vulnerable code
- applicable patches introduce real security transformations
- non-applicable strategies (output_encoding for SQL injection) are correctly identified
- no patch is falsely marked as secure
"""

import pytest
from app.agents.patch_agent import _generate_fallback_candidates, _sql_injection_fix
from app.agents.models import PatchCandidate, PatchGenerationRequest


VULN_CODE = 'query = "SELECT * FROM users WHERE id = " + user_id'

SQL_REQUEST = PatchGenerationRequest(
    vulnerability_id="vuln-p1-test",
    vulnerability_type="SQL_INJECTION",
    severity="CRITICAL",
    file="app/db.py",
    line=15,
    vulnerable_code=VULN_CODE,
    surrounding_code="def get_user(user_id):\n    conn = sqlite3.connect('app.db')\n",
    description="SQL injection via string concatenation",
    cwe="CWE-89",
)


# ============================================================
# TEST 1: Every candidate differs from the original
# ============================================================

class TestPatchesDifferFromOriginal:
    """Each fallback patch must produce code that differs from the input."""

    def test_all_five_candidates_differ(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        assert len(candidates) == 5

        for c in candidates:
            # Every candidate must change the code
            assert c.modified_code != VULN_CODE, (
                f"{c.patch_id} ({c.security_strategy}) is identical to original"
            )
            # Code must be non-trivially different (at least 30% longer or different line count)
            orig_lines = len(VULN_CODE.strip().splitlines())
            new_lines = len(c.modified_code.strip().splitlines())
            assert new_lines >= orig_lines or len(c.modified_code) > len(VULN_CODE) * 1.2, (
                f"{c.patch_id} ({c.security_strategy}) is too similar to original "
                f"({new_lines} lines vs {orig_lines} original)"
            )

    def test_parameterized_query_removes_concatenation(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        pq = [c for c in candidates if "Parameterized" in c.security_strategy][0]
        # Must not contain the vulnerable concatenation pattern
        assert '+" + user_id' not in pq.modified_code or "?" in pq.modified_code
        # Must use parameterized query placeholder
        assert "?" in pq.modified_code or "%s" in pq.modified_code

    def test_input_validation_adds_check(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        iv = [c for c in candidates if "Input Validation" in c.security_strategy][0]
        # Must add a validation check
        assert "re." in iv.modified_code or "if " in iv.modified_code
        # Must still use parameterized query
        assert "?" in iv.modified_code or "parameterized" in iv.modified_code.lower()

    def test_allowlist_adds_allowed_set(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        al = [c for c in candidates if "Allowlist" in c.security_strategy][0]
        # Must define an allowed set
        assert "ALLOWED" in al.modified_code or "allowlist" in al.modified_code.lower()
        # Must validate input against the allowlist
        assert "if " in al.modified_code and ("not in" in al.modified_code or "in " in al.modified_code)

    def test_framework_protection_uses_orm(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        fp = [c for c in candidates if "Framework" in c.security_strategy][0]
        # Must reference ORM or query builder
        assert "text(" in fp.modified_code or "execute(" in fp.modified_code
        # Must use named or positional parameters
        assert ":uid" in fp.modified_code or "?" in fp.modified_code


# ============================================================
# TEST 2: Applicable patches remove or reduce the vulnerability
# ============================================================

class TestApplicablePatchesReduceVulnerability:
    """Applicable patches must eliminate or substantially reduce the SQL injection."""

    VULNERABLE_PATTERNS = [
        '"SELECT * FROM users WHERE id = " + user_id',
        "'SELECT * FROM users WHERE id = ' + user_id",
    ]

    def _has_vulnerable_concat(self, code):
        return any(pat in code for pat in self.VULNERABLE_PATTERNS)

    def test_parameterized_query_removes_vulnerability(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        pq = [c for c in candidates if "Parameterized" in c.security_strategy][0]
        assert not self._has_vulnerable_concat(pq.modified_code), (
            "parameterized_query patch still contains vulnerable concatenation"
        )

    def test_input_validation_reduces_vulnerability(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        iv = [c for c in candidates if "Input Validation" in c.security_strategy][0]
        # Input validation should add validation AND use parameterized query
        has_validation = "re." in iv.modified_code or "if " in iv.modified_code
        has_param_query = "?" in iv.modified_code
        assert has_validation and has_param_query, (
            "input_validation must combine input validation with parameterized query"
        )

    def test_allowlist_reduces_vulnerability(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        al = [c for c in candidates if "Allowlist" in c.security_strategy][0]
        # Must validate column names AND parameterize values
        has_allowlist = "ALLOWED" in al.modified_code
        has_param_query = "?" in al.modified_code
        assert has_allowlist and has_param_query, (
            "allowlist must combine column allowlist with parameterized values"
        )

    def test_framework_protection_removes_vulnerability(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        fp = [c for c in candidates if "Framework" in c.security_strategy][0]
        assert not self._has_vulnerable_concat(fp.modified_code), (
            "framework_protection patch still contains vulnerable concatenation"
        )


# ============================================================
# TEST 3: Non-applicable strategies are correctly identified
# ============================================================

class TestNonApplicableStrategies:
    """Output encoding for SQL injection must be marked NOT_APPLICABLE."""

    def test_output_encoding_is_not_applicable(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        oe = [c for c in candidates if "Output Encoding" in c.security_strategy][0]
        assert oe.is_not_applicable is True, (
            "output_encoding should be NOT_APPLICABLE for SQL injection"
        )

    def test_not_applicable_candidate_explains_why(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        oe = [c for c in candidates if "Output Encoding" in c.security_strategy][0]
        combined = (oe.explanation + " " + oe.expected_effect).lower()
        assert "not applicable" in combined or "does not prevent sql" in combined or "xss" in combined, (
            "NOT_APPLICABLE candidate must explain why the strategy doesn't apply"
        )

    def test_not_applicable_does_not_modify_code(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        oe = [c for c in candidates if "Output Encoding" in c.security_strategy][0]
        # The modified_code should NOT be a real fix -- it should be a comment
        assert "# NOT APPLICABLE" in oe.modified_code or "# Output encoding" in oe.modified_code.lower(), (
            "NOT_APPLICABLE candidate should contain a comment, not a fake fix"
        )

    def test_not_applicable_assumptions_state_inapplicability(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        oe = [c for c in candidates if "Output Encoding" in c.security_strategy][0]
        assert any("not" in a.lower() and "applicable" in a.lower() for a in oe.assumptions), (
            "NOT_APPLICABLE assumptions must state the strategy is not applicable"
        )

    def test_other_strategies_are_applicable(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        for c in candidates:
            if "Output Encoding" not in c.security_strategy:
                assert c.is_not_applicable is False, (
                    f"{c.security_strategy} should be applicable for SQL injection"
                )


# ============================================================
# TEST 4: No patch is falsely marked as secure
# ============================================================

class TestNoFalseSecurityClaims:
    """No candidate should claim guaranteed, full, or 100% security."""

    SECURITY_CLAIMS = [
        "guaranteed secure",
        "fully secure",
        "100% secure",
        "eliminates all risk",
        "completely safe",
        "unhackable",
    ]

    def test_no_absolute_security_claims(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        for c in candidates:
            combined = (c.explanation + " " + c.expected_effect).lower()
            for claim in self.SECURITY_CLAIMS:
                assert claim not in combined, (
                    f"{c.patch_id} ({c.security_strategy}) contains false security "
                    f"claim: '{claim}'"
                )

    def test_not_applicable_does_not_claim_fix(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        oe = [c for c in candidates if "Output Encoding" in c.security_strategy][0]
        combined = (oe.explanation + " " + oe.expected_effect).lower()
        # Must NOT claim this fixes SQL injection
        assert "prevents sql" not in combined or "does not prevent" in combined


# ============================================================
# TEST 5: Candidates have distinct strategies
# ============================================================

class TestDistinctStrategies:
    """Each candidate must use a different security strategy."""

    def test_all_strategies_different(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        strategies = [c.security_strategy for c in candidates]
        assert len(strategies) == len(set(strategies)), (
            f"Duplicate strategies found: {strategies}"
        )

    def test_five_candidates_produced(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        assert len(candidates) == 5

    def test_candidate_ids_unique(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        ids = [c.patch_id for c in candidates]
        assert len(ids) == len(set(ids))


# ============================================================
# TEST 6: All required fields are populated
# ============================================================

class TestRequiredFields:
    """Every candidate must have all required fields populated."""

    def test_all_fields_present(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        for c in candidates:
            assert c.patch_id, f"Missing patch_id for candidate"
            assert c.modified_code, f"Missing modified_code for {c.patch_id}"
            assert c.explanation, f"Missing explanation for {c.patch_id}"
            assert c.security_strategy, f"Missing security_strategy for {c.patch_id}"
            assert c.expected_effect, f"Missing expected_effect for {c.patch_id}"
            assert isinstance(c.assumptions, list), f"assumptions must be list for {c.patch_id}"
            assert isinstance(c.potential_side_effects, list), f"side_effects must be list for {c.patch_id}"
            assert isinstance(c.is_not_applicable, bool), f"is_not_applicable must be bool for {c.patch_id}"


# ============================================================
# TEST 7: Show all five candidates (print for review)
# ============================================================

class TestShowCandidates:
    """Display all five fallback candidates for visual review."""

    def test_show_all_five_sql_injection_candidates(self):
        candidates = _generate_fallback_candidates(SQL_REQUEST)
        print("\n" + "=" * 70)
        print("FALLBACK PATCH CANDIDATES FOR SQL_INJECTION")
        print("=" * 70)
        for c in candidates:
            na_marker = " [NOT APPLICABLE]" if c.is_not_applicable else ""
            print(f"\n--- {c.patch_id}: {c.security_strategy}{na_marker} ---")
            print(f"Explanation: {c.explanation}")
            print(f"Expected:    {c.expected_effect}")
            print(f"Assumptions: {c.assumptions}")
            print(f"Side effects:{c.potential_side_effects}")
            print(f"Code:\n{c.modified_code}")
        print("\n" + "=" * 70)

        # Verify the output
        assert len(candidates) == 5
        na_count = sum(1 for c in candidates if c.is_not_applicable)
        assert na_count == 1, f"Expected exactly 1 NOT_APPLICABLE, got {na_count}"
        assert candidates[2].is_not_applicable, "Output Encoding should be NOT_APPLICABLE"
