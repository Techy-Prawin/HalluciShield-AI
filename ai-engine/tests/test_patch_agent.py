"""
Patch Generation Agent Test Suite for HalluciShield AI.

Tests multi-candidate patch generation for:
- Malformed LLM responses (JSON errors, missing fields, wrong types)
- Valid LLM responses
- Fallback deterministic generation
- API endpoint behavior
- Retry handling
- Structured JSON validation
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.agents.patch_agent import (
    PatchGenerationAgent,
    _parse_llm_response,
    _validate_patch,
    _generate_fallback_candidates,
    _build_prompt,
    NUM_CANDIDATES,
    MAX_RETRIES,
    REQUIRED_PATCH_FIELDS,
)
from app.agents.models import (
    PatchCandidate,
    PatchGenerationRequest,
    PatchGenerationResponse,
)

client = TestClient(app)


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def agent():
    return PatchGenerationAgent()


@pytest.fixture
def sql_injection_request():
    return PatchGenerationRequest(
        vulnerability_id="vuln-001",
        vulnerability_type="SQL_INJECTION",
        severity="CRITICAL",
        file="app/db.py",
        line=15,
        vulnerable_code='query = "SELECT * FROM users WHERE id = " + user_id',
        surrounding_code="def get_user(user_id):\n    conn = sqlite3.connect('app.db')\n    cursor = conn.cursor()\n",
        description="SQL injection via string concatenation",
        cwe="CWE-89",
    )


@pytest.fixture
def xss_request():
    return PatchGenerationRequest(
        vulnerability_id="vuln-002",
        vulnerability_type="CROSS_SITE_SCRIPTING",
        severity="HIGH",
        file="app/templates.py",
        line=42,
        vulnerable_code="element.innerHTML = user_input",
        surrounding_code="def render_comment(comment):\n    element = document.getElementById('output')\n",
        description="XSS via innerHTML assignment",
        cwe="CWE-79",
    )


@pytest.fixture
def valid_llm_response():
    patches = []
    for i in range(1, 6):
        patches.append({
            "patch_id": f"patch-{i}",
            "modified_code": f"# Candidate {i} fix\ncursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            "explanation": f"Candidate {i}: Uses parameterized query to prevent SQL injection.",
            "security_strategy": "Parameterized Query",
            "assumptions": ["Database supports parameterized queries", "user_id is validated"],
            "expected_effect": "Prevents SQL injection by separating query from data.",
            "potential_side_effects": ["May change query performance characteristics"],
        })
    return json.dumps(patches)


@pytest.fixture
def malformed_responses():
    return {
        "not_json": "This is not JSON at all",
        "empty_json": "{}",
        "empty_array": "[]",
        "missing_fields": json.dumps([
            {"patch_id": "patch-1", "modified_code": "fixed code"}
        ]),
        "wrong_types": json.dumps([
            {
                "patch_id": 123,
                "modified_code": ["not", "a", "string"],
                "explanation": True,
                "security_strategy": None,
                "assumptions": "not a list",
                "expected_effect": 42,
                "potential_side_effects": "also not a list",
            }
        ]),
        "nested_object": json.dumps({"patches": [
            {
                "patch_id": "patch-1",
                "modified_code": "code",
                "explanation": "explanation",
                "security_strategy": "strategy",
                "assumptions": [],
                "expected_effect": "effect",
                "potential_side_effects": [],
            }
        ]}),
        "string_instead_of_array": json.dumps("just a string"),
        "array_of_strings": json.dumps(["patch-1", "patch-2"]),
        "partial_valid": json.dumps([
            {
                "patch_id": "patch-1",
                "modified_code": "valid code",
                "explanation": "valid explanation",
                "security_strategy": "valid strategy",
                "assumptions": [],
                "expected_effect": "valid effect",
                "potential_side_effects": [],
            },
            {"patch_id": "patch-2"},
            {
                "patch_id": "patch-3",
                "modified_code": "code3",
                "explanation": "expl3",
                "security_strategy": "strat3",
                "assumptions": [],
                "expected_effect": "effect3",
                "potential_side_effects": [],
            },
        ]),
        "markdown_wrapped": "```json\n" + json.dumps([
            {
                "patch_id": "patch-1",
                "modified_code": "code",
                "explanation": "explanation",
                "security_strategy": "strategy",
                "assumptions": [],
                "expected_effect": "effect",
                "potential_side_effects": [],
            }
        ]) + "\n```",
    }


# ============================================================
# Test _validate_patch
# ============================================================

class TestValidatePatch:
    """Tests for single patch validation."""

    def test_valid_patch_passes(self):
        raw = {
            "patch_id": "patch-1",
            "modified_code": "fixed code here",
            "explanation": "This fixes the issue",
            "security_strategy": "Input validation",
            "assumptions": ["Input is user-controlled"],
            "expected_effect": "Blocks malicious input",
            "potential_side_effects": ["May reject some valid inputs"],
        }
        result = _validate_patch(raw)
        assert result is not None
        assert result.patch_id == "patch-1"
        assert result.modified_code == "fixed code here"
        assert len(result.assumptions) == 1

    def test_none_input_returns_none(self):
        assert _validate_patch(None) is None

    def test_string_input_returns_none(self):
        assert _validate_patch("not a dict") is None

    def test_missing_required_field_returns_none(self):
        raw = {
            "patch_id": "patch-1",
            "modified_code": "code",
            # missing explanation, security_strategy, etc.
        }
        assert _validate_patch(raw) is None

    def test_empty_modified_code_returns_none(self):
        raw = {
            "patch_id": "patch-1",
            "modified_code": "",
            "explanation": "explanation",
            "security_strategy": "strategy",
            "assumptions": [],
            "expected_effect": "effect",
            "potential_side_effects": [],
        }
        assert _validate_patch(raw) is None

    def test_empty_explanation_returns_none(self):
        raw = {
            "patch_id": "patch-1",
            "modified_code": "code",
            "explanation": "",
            "security_strategy": "strategy",
            "assumptions": [],
            "expected_effect": "effect",
            "potential_side_effects": [],
        }
        assert _validate_patch(raw) is None

    def test_string_assumptions_converted_to_list(self):
        raw = {
            "patch_id": "patch-1",
            "modified_code": "code",
            "explanation": "explanation",
            "security_strategy": "strategy",
            "assumptions": "single assumption",
            "expected_effect": "effect",
            "potential_side_effects": [],
        }
        result = _validate_patch(raw)
        assert result is not None
        assert result.assumptions == ["single assumption"]

    def test_non_list_assumptions_become_empty(self):
        raw = {
            "patch_id": "patch-1",
            "modified_code": "code",
            "explanation": "explanation",
            "security_strategy": "strategy",
            "assumptions": 123,
            "expected_effect": "effect",
            "potential_side_effects": [],
        }
        result = _validate_patch(raw)
        assert result is not None
        assert result.assumptions == []

    def test_string_side_effects_converted_to_list(self):
        raw = {
            "patch_id": "patch-1",
            "modified_code": "code",
            "explanation": "explanation",
            "security_strategy": "strategy",
            "assumptions": [],
            "expected_effect": "effect",
            "potential_side_effects": "one side effect",
        }
        result = _validate_patch(raw)
        assert result is not None
        assert result.potential_side_effects == ["one side effect"]


# ============================================================
# Test _parse_llm_response
# ============================================================

class TestParseLLMResponse:
    """Tests for parsing and validating LLM response text."""

    def test_valid_json_array(self, valid_llm_response):
        candidates = _parse_llm_response(valid_llm_response)
        assert len(candidates) == 5
        for c in candidates:
            assert isinstance(c, PatchCandidate)
            assert c.patch_id.startswith("patch-")

    def test_invalid_json_raises_error(self):
        with pytest.raises((json.JSONDecodeError, ValueError)):
            _parse_llm_response("this is not json {{{")

    def test_empty_array_returns_empty(self):
        result = _parse_llm_response("[]")
        assert result == []

    def test_object_with_patches_key(self):
        data = json.dumps({
            "patches": [
                {
                    "patch_id": "patch-1",
                    "modified_code": "code",
                    "explanation": "expl",
                    "security_strategy": "strat",
                    "assumptions": [],
                    "expected_effect": "effect",
                    "potential_side_effects": [],
                }
            ]
        })
        result = _parse_llm_response(data)
        assert len(result) == 1

    def test_object_with_candidates_key(self):
        data = json.dumps({
            "candidates": [
                {
                    "patch_id": "patch-1",
                    "modified_code": "code",
                    "explanation": "expl",
                    "security_strategy": "strat",
                    "assumptions": [],
                    "expected_effect": "effect",
                    "potential_side_effects": [],
                }
            ]
        })
        result = _parse_llm_response(data)
        assert len(result) == 1

    def test_markdown_wrapped_json(self):
        raw = '```json\n[{"patch_id":"patch-1","modified_code":"c","explanation":"e","security_strategy":"s","assumptions":[],"expected_effect":"ef","potential_side_effects":[]}]\n```'
        result = _parse_llm_response(raw)
        assert len(result) == 1

    def test_filters_invalid_patches(self):
        data = json.dumps([
            {
                "patch_id": "patch-1",
                "modified_code": "code",
                "explanation": "expl",
                "security_strategy": "strat",
                "assumptions": [],
                "expected_effect": "effect",
                "potential_side_effects": [],
            },
            {"patch_id": "bad-patch"},
            {
                "patch_id": "patch-2",
                "modified_code": "code2",
                "explanation": "expl2",
                "security_strategy": "strat2",
                "assumptions": [],
                "expected_effect": "effect2",
                "potential_side_effects": [],
            },
        ])
        result = _parse_llm_response(data)
        assert len(result) == 2
        assert all(c.patch_id in ("patch-1", "patch-2") for c in result)

    def test_string_instead_of_array_raises(self):
        with pytest.raises(ValueError):
            _parse_llm_response('"just a string"')

    def test_array_of_strings_filters_all(self):
        result = _parse_llm_response('["patch-1", "patch-2"]')
        assert result == []


# ============================================================
# Test malformed responses (key requirement)
# ============================================================

class TestMalformedResponses:
    """Tests specifically for malformed model responses."""

    def test_not_json_at_all(self):
        with pytest.raises((json.JSONDecodeError, ValueError)):
            _parse_llm_response("This is not JSON at all")

    def test_empty_object(self):
        with pytest.raises(ValueError, match="Expected JSON array"):
            _parse_llm_response("{}")

    def test_wrong_types_filtered(self):
        data = json.dumps([{
            "patch_id": 123,
            "modified_code": ["not", "a", "string"],
            "explanation": True,
            "security_strategy": None,
            "assumptions": "not a list",
            "expected_effect": 42,
            "potential_side_effects": "also not a list",
        }])
        result = _parse_llm_response(data)
        assert result == []

    def test_nested_object_with_patches_key(self):
        data = json.dumps({
            "result": {
                "patches": [
                    {
                        "patch_id": "patch-1",
                        "modified_code": "code",
                        "explanation": "expl",
                        "security_strategy": "strat",
                        "assumptions": [],
                        "expected_effect": "effect",
                        "potential_side_effects": [],
                    }
                ]
            }
        })
        with pytest.raises(ValueError, match="Expected JSON array"):
            _parse_llm_response(data)

    def test_partial_valid_patches(self):
        data = json.dumps([
            {
                "patch_id": "patch-1",
                "modified_code": "valid",
                "explanation": "valid",
                "security_strategy": "valid",
                "assumptions": [],
                "expected_effect": "valid",
                "potential_side_effects": [],
            },
            {"patch_id": "incomplete"},
            {
                "patch_id": "patch-3",
                "modified_code": "code",
                "explanation": "expl",
                "security_strategy": "strat",
                "assumptions": [],
                "expected_effect": "effect",
                "potential_side_effects": [],
            },
        ])
        result = _parse_llm_response(data)
        assert len(result) == 2


# ============================================================
# Test _build_prompt
# ============================================================

class TestBuildPrompt:
    """Tests for prompt construction."""

    def test_prompt_includes_vulnerability_type(self, sql_injection_request):
        prompt = _build_prompt(sql_injection_request)
        assert "SQL_INJECTION" in prompt

    def test_prompt_includes_vulnerable_code(self, sql_injection_request):
        prompt = _build_prompt(sql_injection_request)
        assert "SELECT * FROM users" in prompt

    def test_prompt_includes_severity(self, sql_injection_request):
        prompt = _build_prompt(sql_injection_request)
        assert "CRITICAL" in prompt

    def test_prompt_includes_cwe(self, sql_injection_request):
        prompt = _build_prompt(sql_injection_request)
        assert "CWE-89" in prompt

    def test_prompt_requests_five_candidates(self, sql_injection_request):
        prompt = _build_prompt(sql_injection_request)
        assert str(NUM_CANDIDATES) in prompt

    def test_prompt_disclaims_security(self, sql_injection_request):
        prompt = _build_prompt(sql_injection_request)
        assert "candidate" in prompt.lower()


# ============================================================
# Test fallback generation
# ============================================================

class TestFallbackGeneration:
    """Tests for deterministic fallback patch generation."""

    def test_generates_exactly_five_candidates(self, sql_injection_request):
        candidates = _generate_fallback_candidates(sql_injection_request)
        assert len(candidates) == 5

    def test_all_candidates_are_patch_candidate(self, sql_injection_request):
        candidates = _generate_fallback_candidates(sql_injection_request)
        for c in candidates:
            assert isinstance(c, PatchCandidate)

    def test_unique_patch_ids(self, sql_injection_request):
        candidates = _generate_fallback_candidates(sql_injection_request)
        ids = [c.patch_id for c in candidates]
        assert len(ids) == len(set(ids))

    def test_all_required_fields_populated(self, sql_injection_request):
        candidates = _generate_fallback_candidates(sql_injection_request)
        for c in candidates:
            assert c.patch_id
            assert c.modified_code
            assert c.explanation
            assert c.security_strategy
            assert c.expected_effect
            assert isinstance(c.assumptions, list)
            assert isinstance(c.potential_side_effects, list)

    def test_sql_injection_type_generates_relevant_fixes(self, sql_injection_request):
        candidates = _generate_fallback_candidates(sql_injection_request)
        strategies = [c.security_strategy for c in candidates]
        assert any("Parameterized" in s or "parameterized" in s.lower() for s in strategies)

    def test_xss_type_generates_relevant_fixes(self, xss_request):
        candidates = _generate_fallback_candidates(xss_request)
        assert len(candidates) == 5
        for c in candidates:
            combined = (c.explanation + " " + c.expected_effect).lower()
            assert "cross_site_scripting" in combined or "xss" in combined

    def test_generic_type_for_unknown_vuln(self):
        request = PatchGenerationRequest(
            vulnerability_id="vuln-999",
            vulnerability_type="UNKNOWN_TYPE",
            severity="MEDIUM",
            file="app.py",
            line=10,
            vulnerable_code="code = input()",
        )
        candidates = _generate_fallback_candidates(request)
        assert len(candidates) == 5

    def test_candidate_not_claiming_security(self, sql_injection_request):
        """Candidates must NOT claim the patch is secure."""
        candidates = _generate_fallback_candidates(sql_injection_request)
        for c in candidates:
            lower_expl = c.explanation.lower()
            lower_strategy = c.security_strategy.lower()
            # Should not contain absolute security claims
            assert "guaranteed secure" not in lower_expl
            assert "fully secure" not in lower_expl
            assert "100% secure" not in lower_expl


# ============================================================
# Test PatchGenerationAgent
# ============================================================

class TestPatchGenerationAgent:
    """Tests for the full patch generation agent."""

    def test_agent_initialization(self, agent):
        assert agent is not None

    @patch("app.agents.patch_agent._query_llm")
    def test_agent_returns_five_candidates(self, mock_llm, agent, sql_injection_request):
        mock_llm.return_value = ("", 0)
        response = agent.generate_patches(sql_injection_request)
        assert isinstance(response, PatchGenerationResponse)
        assert len(response.candidates) == 5

    @patch("app.agents.patch_agent._query_llm")
    def test_agent_uses_fallback_when_llm_unavailable(self, mock_llm, agent, sql_injection_request):
        mock_llm.return_value = ("", 0)
        response = agent.generate_patches(sql_injection_request)
        assert response.model_used == "deterministic-fallback"

    @patch("app.agents.patch_agent._query_llm")
    def test_agent_validates_llm_response(self, mock_llm, agent, sql_injection_request):
        # LLM returns malformed JSON
        mock_llm.return_value = ("not json", 0)
        response = agent.generate_patches(sql_injection_request)
        assert len(response.candidates) == 5
        assert response.model_used == "deterministic-fallback"
        assert response.retry_count > 0

    @patch("app.agents.patch_agent._query_llm")
    def test_agent_retries_on_malformed_response(self, mock_llm, agent, sql_injection_request):
        call_count = 0

        def side_effect(prompt, attempt=0):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return ("not json", 0)
            return ("", 0)

        mock_llm.side_effect = side_effect
        response = agent.generate_patches(sql_injection_request)
        assert response.retry_count >= 2

    @patch("app.agents.patch_agent._query_llm")
    def test_agent_uses_llm_when_valid(self, mock_llm, agent, sql_injection_request, valid_llm_response):
        mock_llm.return_value = (valid_llm_response, 0)
        response = agent.generate_patches(sql_injection_request)
        assert len(response.candidates) == 5
        assert response.model_used != "deterministic-fallback"

    @patch("app.agents.patch_agent._query_llm")
    def test_agent_truncates_to_five(self, mock_llm, agent, sql_injection_request):
        # LLM returns more than 5 candidates
        patches = []
        for i in range(8):
            patches.append({
                "patch_id": f"patch-{i}",
                "modified_code": f"code {i}",
                "explanation": f"explanation {i}",
                "security_strategy": f"strategy {i}",
                "assumptions": [],
                "expected_effect": f"effect {i}",
                "potential_side_effects": [],
            })
        mock_llm.return_value = (json.dumps(patches), 0)
        response = agent.generate_patches(sql_injection_request)
        assert len(response.candidates) == 5

    @patch("app.agents.patch_agent._query_llm")
    def test_agent_pads_short_llm_response(self, mock_llm, agent, sql_injection_request):
        # LLM returns fewer than 5 valid candidates
        patches = [
            {
                "patch_id": "patch-1",
                "modified_code": "code",
                "explanation": "expl",
                "security_strategy": "strat",
                "assumptions": [],
                "expected_effect": "effect",
                "potential_side_effects": [],
            },
        ]
        mock_llm.return_value = (json.dumps(patches), 0)
        response = agent.generate_patches(sql_injection_request)
        assert len(response.candidates) == 5

    @patch("app.agents.patch_agent._query_llm")
    def test_agent_records_retry_count(self, mock_llm, agent, sql_injection_request):
        mock_llm.return_value = ("bad json {{{", 2)
        response = agent.generate_patches(sql_injection_request)
        assert response.retry_count >= 2

    @patch("app.agents.patch_agent._query_llm")
    def test_agent_records_generation_time(self, mock_llm, agent, sql_injection_request):
        mock_llm.return_value = ("", 0)
        response = agent.generate_patches(sql_injection_request)
        assert response.generation_duration_ms >= 0

    @patch("app.agents.patch_agent._query_llm")
    def test_agent_does_not_claim_security(self, mock_llm, agent, sql_injection_request):
        mock_llm.return_value = ("", 0)
        response = agent.generate_patches(sql_injection_request)
        for c in response.candidates:
            assert "guaranteed secure" not in c.explanation.lower()
            assert "fully secure" not in c.explanation.lower()

    @patch("app.agents.patch_agent._query_llm")
    def test_agent_records_model_used(self, mock_llm, agent, sql_injection_request):
        mock_llm.return_value = ("", 0)
        response = agent.generate_patches(sql_injection_request)
        assert response.model_used == "deterministic-fallback"


# ============================================================
# Test API Endpoint
# ============================================================

class TestPatchGenerationEndpoint:
    """Tests for the POST /api/vulnerabilities/:id/generate-patches endpoint."""

    @patch("app.api.patches.agent_instance")
    def test_endpoint_returns_200(self, mock_agent):
        mock_agent.generate_patches.return_value = PatchGenerationResponse(
            vulnerability_id="vuln-001",
            candidates=[
                PatchCandidate(
                    patch_id=f"patch-{i}",
                    modified_code=f"code {i}",
                    explanation=f"explanation {i}",
                    security_strategy=f"strategy {i}",
                    assumptions=[],
                    expected_effect=f"effect {i}",
                    potential_side_effects=[],
                )
                for i in range(1, 6)
            ],
            generation_duration_ms=100,
            model_used="test-model",
        )

        response = client.post(
            "/api/v1/vulnerabilities/vuln-001/generate-patches",
            json={
                "vulnerability_id": "vuln-001",
                "vulnerability_type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "file": "app.py",
                "line": 10,
                "vulnerable_code": "query = 'SELECT * FROM users WHERE id = ' + user_id",
                "surrounding_code": "",
                "description": "SQL injection",
                "cwe": "CWE-89",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["candidates"]) == 5
        assert data["vulnerability_id"] == "vuln-001"

    def test_endpoint_returns_400_on_empty_code(self):
        response = client.post(
            "/api/v1/vulnerabilities/vuln-001/generate-patches",
            json={
                "vulnerability_id": "vuln-001",
                "vulnerability_type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "file": "app.py",
                "line": 10,
                "vulnerable_code": "   ",
            },
        )
        assert response.status_code == 400

    def test_endpoint_returns_422_on_missing_fields(self):
        response = client.post(
            "/api/v1/vulnerabilities/vuln-001/generate-patches",
            json={},
        )
        assert response.status_code == 422

    @patch("app.api.patches.agent_instance")
    def test_endpoint_returns_500_on_agent_error(self, mock_agent):
        mock_agent.generate_patches.side_effect = RuntimeError("Agent crashed")
        response = client.post(
            "/api/v1/vulnerabilities/vuln-001/generate-patches",
            json={
                "vulnerability_id": "vuln-001",
                "vulnerability_type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "file": "app.py",
                "line": 10,
                "vulnerable_code": "query = 'bad'",
            },
        )
        assert response.status_code == 500

    @patch("app.api.patches.agent_instance")
    def test_endpoint_returns_correct_response_model(self, mock_agent):
        mock_agent.generate_patches.return_value = PatchGenerationResponse(
            vulnerability_id="vuln-002",
            candidates=[
                PatchCandidate(
                    patch_id=f"patch-{i}",
                    modified_code=f"code {i}",
                    explanation=f"expl {i}",
                    security_strategy=f"strat {i}",
                    assumptions=[f"assumption {i}"],
                    expected_effect=f"effect {i}",
                    potential_side_effects=[f"side effect {i}"],
                )
                for i in range(1, 6)
            ],
            generation_duration_ms=250,
            model_used="deepseek-coder:6.7b",
            retry_count=1,
        )

        response = client.post(
            "/api/v1/vulnerabilities/vuln-002/generate-patches",
            json={
                "vulnerability_id": "vuln-002",
                "vulnerability_type": "CROSS_SITE_SCRIPTING",
                "severity": "HIGH",
                "file": "app.js",
                "line": 42,
                "vulnerable_code": "element.innerHTML = userInput",
            },
        )
        data = response.json()
        assert data["vulnerability_id"] == "vuln-002"
        assert data["generation_duration_ms"] == 250
        assert data["model_used"] == "deepseek-coder:6.7b"
        assert data["retry_count"] == 1
        for candidate in data["candidates"]:
            assert "patch_id" in candidate
            assert "modified_code" in candidate
            assert "explanation" in candidate
            assert "security_strategy" in candidate
            assert "assumptions" in candidate
            assert "expected_effect" in candidate
            assert "potential_side_effects" in candidate


# ============================================================
# Test edge cases
# ============================================================

class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_num_candidates_constant(self):
        assert NUM_CANDIDATES == 5

    def test_max_retries_constant(self):
        assert MAX_RETRIES == 3

    def test_required_fields_complete(self):
        expected = {
            "patch_id", "modified_code", "explanation",
            "security_strategy", "assumptions", "expected_effect",
            "potential_side_effects",
        }
        assert REQUIRED_PATCH_FIELDS == expected

    @patch("app.agents.patch_agent._query_llm")
    def test_concurrent_requests(self, mock_llm, sql_injection_request):
        mock_llm.return_value = ("", 0)
        agent = PatchGenerationAgent()
        responses = []
        for _ in range(3):
            resp = agent.generate_patches(sql_injection_request)
            responses.append(resp)
        for r in responses:
            assert len(r.candidates) == 5

    @patch("app.agents.patch_agent._query_llm")
    def test_all_vuln_types_fallback(self, mock_llm):
        mock_llm.return_value = ("", 0)
        agent = PatchGenerationAgent()
        types = ["SQL_INJECTION", "CROSS_SITE_SCRIPTING", "HARDCODED_SECRET",
                 "COMMAND_INJECTION", "PATH_TRAVERSAL", "INSECURE_JWT", "UNKNOWN"]
        for vtype in types:
            req = PatchGenerationRequest(
                vulnerability_id=f"vuln-{vtype}",
                vulnerability_type=vtype,
                severity="HIGH",
                file="app.py",
                line=1,
                vulnerable_code="code",
            )
            resp = agent.generate_patches(req)
            assert len(resp.candidates) == 5
