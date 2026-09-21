"""
Multi-Candidate Patch Generation Agent for HalluciShield AI.

Generates exactly 5 candidate patches per vulnerability.
Each candidate is a suggestion, NOT a claim of security.

Uses LLM with structured JSON output and retry handling.
Validates every model response structurally before accepting.
"""

import json
import logging
import time
import uuid
from typing import List, Optional, Tuple

from app.config import settings
from app.agents.models import (
    PatchCandidate,
    PatchGenerationRequest,
    PatchGenerationResponse,
)
from app.agents.database import store_patch_candidates
from app.agents.llm_client import chat_json
from app.security import sanitize_for_llm_prompt

logger = logging.getLogger(__name__)

REQUIRED_PATCH_FIELDS = {
    "patch_id",
    "modified_code",
    "explanation",
    "security_strategy",
    "assumptions",
    "expected_effect",
    "potential_side_effects",
}

NUM_CANDIDATES = 5
MAX_RETRIES = 3
RETRY_DELAY_BASE = 1.0


def _build_prompt(request: PatchGenerationRequest) -> str:
    safe_vuln_code = sanitize_for_llm_prompt(request.vulnerable_code)
    safe_surrounding = sanitize_for_llm_prompt(request.surrounding_code)
    safe_desc = sanitize_for_llm_prompt(request.description)
    return f"""You are a security patch generation assistant.
Given a vulnerability finding and its source code, generate exactly {NUM_CANDIDATES} DIFFERENT candidate patches.

IMPORTANT: These are CANDIDATE patches only. Do NOT claim any patch makes the code secure.
Each patch represents one possible remediation approach.

Vulnerability:
- Type: {request.vulnerability_type}
- Severity: {request.severity}
- CWE: {request.cwe or "N/A"}
- File: {request.file}
- Line: {request.line}
- Description: {safe_desc}

Vulnerable code:
```{request.file.split('.')[-1] if '.' in request.file else 'code'}
{safe_vuln_code}
```

Surrounding code context:
```
{safe_surrounding}
```

Respond with ONLY a valid JSON array of exactly {NUM_CANDIDATES} objects. No markdown, no explanation outside JSON.
Each object must have these EXACT keys:
[
  {{
    "patch_id": "patch-1",
    "modified_code": "<the full modified code snippet>",
    "explanation": "<what this patch does>",
    "security_strategy": "<the security approach used>",
    "assumptions": ["<assumption 1>", "<assumption 2>"],
    "expected_effect": "<what this patch is expected to achieve>",
    "potential_side_effects": ["<side effect 1>", "<side effect 2>"]
  }}
]

Generate {NUM_CANDIDATES} patches using DIFFERENT strategies (e.g., input validation, parameterized queries, escaping, allowlisting, framework-native protections).
"""


def _validate_patch(raw: dict) -> Optional[PatchCandidate]:
    """Validate a single raw patch dict against required fields. Returns PatchCandidate or None."""
    if not isinstance(raw, dict):
        return None

    missing = REQUIRED_PATCH_FIELDS - set(raw.keys())
    if missing:
        logger.debug(f"[PatchGen] Missing fields in patch: {missing}")
        return None

    # Reject non-string required fields
    for field in ("patch_id", "modified_code", "explanation", "security_strategy", "expected_effect"):
        val = raw.get(field)
        if not isinstance(val, str) or not val.strip():
            logger.debug(f"[PatchGen] Field '{field}' must be a non-empty string, got {type(val).__name__}")
            return None

    # Ensure list fields are actually lists
    assumptions = raw["assumptions"]
    if isinstance(assumptions, str):
        assumptions = [assumptions]
    elif not isinstance(assumptions, list):
        assumptions = []

    side_effects = raw["potential_side_effects"]
    if isinstance(side_effects, str):
        side_effects = [side_effects]
    elif not isinstance(side_effects, list):
        side_effects = []

    return PatchCandidate(
        patch_id=raw["patch_id"],
        modified_code=raw["modified_code"],
        explanation=raw["explanation"],
        security_strategy=raw["security_strategy"],
        assumptions=assumptions,
        expected_effect=raw["expected_effect"],
        potential_side_effects=side_effects,
    )


def _parse_llm_response(raw_text: str) -> List[PatchCandidate]:
    """Parse and validate LLM response text into a list of PatchCandidate."""
    text = raw_text.strip()

    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines)

    data = json.loads(text)

    # Handle both array and object wrapper
    if isinstance(data, dict):
        for key in ("patches", "candidates", "fixes", "suggestions"):
            if key in data and isinstance(data[key], list):
                data = data[key]
                break

    if not isinstance(data, list):
        raise ValueError(f"Expected JSON array, got {type(data).__name__}")

    candidates = []
    for item in data:
        patch = _validate_patch(item)
        if patch:
            candidates.append(patch)

    return candidates


def _query_llm(prompt: str, attempt: int = 0) -> Tuple[str, int]:
    """
    Query LLM via the configured provider (OpenAI-compatible or Ollama).
    Returns (raw_response_text, retry_count).
    Falls back to deterministic patch generation if LLM is unavailable.
    """
    try:
        raw_text = chat_json(prompt, timeout=30.0, temperature=0.7, max_tokens=4096)
        if raw_text:
            return raw_text, attempt
    except Exception as e:
        logger.debug(f"[PatchGen] LLM query failed: {e}")

    return "", attempt


def _generate_fallback_candidates(request: PatchGenerationRequest) -> List[PatchCandidate]:
    """
    Deterministic fallback patch generation when LLM is unavailable.
    Generates 5 structurally valid candidate patches based on vulnerability type.
    """
    vuln_type = request.vulnerability_type.upper()
    code = request.vulnerable_code.strip()

    strategies = [
        ("input_validation", "Input Validation and Sanitization"),
        ("parameterized_query", "Parameterized Query / Prepared Statement"),
        ("output_encoding", "Output Encoding and Escaping"),
        ("allowlist", "Allowlist-based Restriction"),
        ("framework_protection", "Framework-native Security Control"),
    ]

    candidates = []
    for i, (strategy_key, strategy_name) in enumerate(strategies, 1):
        if "XSS" in vuln_type or "SCRIPT" in vuln_type:
            modified, explanation, expected_effect, is_na = _xss_fix(code, strategy_key)
        elif "COMMAND" in vuln_type:
            modified, explanation, expected_effect, is_na = _command_injection_fix(code, strategy_key)
        elif "PATH" in vuln_type or "TRAVERSAL" in vuln_type:
            modified, explanation, expected_effect, is_na = _path_traversal_fix(code, strategy_key)
        elif "SECRET" in vuln_type or "HARD" in vuln_type or "CREDENTIAL" in vuln_type:
            modified, explanation, expected_effect, is_na = _secret_fix(code, strategy_key)
        elif "SQL" in vuln_type:
            modified, explanation, expected_effect, is_na = _sql_injection_fix(code, strategy_key)
        else:
            modified, explanation, expected_effect, is_na = _generic_fix(code, strategy_key)

        if is_na:
            assumptions = [
                f"Strategy '{strategy_name}' is not semantically applicable to {request.vulnerability_type}",
                "No code modification is performed; the candidate is marked NOT_APPLICABLE",
            ]
            side_effects = [
                "Applying this strategy would not reduce the specified vulnerability",
            ]
        else:
            assumptions = [
                "Input comes from a user-controlled source",
                f"Existing framework is {request.file.split('.')[-1] if '.' in request.file else 'unknown'}",
            ]
            side_effects = [
                "May require additional testing for regressions",
                "Performance impact may vary depending on input volume",
            ]

        candidates.append(PatchCandidate(
            patch_id=f"patch-{i}",
            modified_code=modified,
            explanation=f"Candidate {i}: {explanation}",
            security_strategy=strategy_name,
            assumptions=assumptions,
            expected_effect=expected_effect,
            potential_side_effects=side_effects,
            is_not_applicable=is_na,
        ))

    return candidates


def _sql_injection_fix(code: str, strategy: str) -> Tuple[str, str, str, bool]:
    """
    Generate a SQL injection fix for the given strategy.

    Returns (modified_code, explanation, expected_effect, is_not_applicable).
    """
    if strategy == "parameterized_query":
        modified = (
            "import sqlite3\n"
            "\n"
            "def get_user(user_id):\n"
            "    conn = sqlite3.connect('app.db')\n"
            "    cursor = conn.cursor()\n"
            "    # Use parameterized query -- data never enters the SQL string\n"
            "    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
            "    return cursor.fetchone()\n"
        )
        return (
            modified,
            "Replaces string concatenation with a parameterized query using a "
            "positional placeholder (?). The database driver handles escaping, so "
            "user-supplied values cannot alter the query structure.",
            "Eliminates SQL injection by separating SQL logic from data at the "
            "driver level, regardless of input content.",
            False,
        )

    elif strategy == "input_validation":
        modified = (
            "import re\n"
            "\n"
            "def get_user(user_id):\n"
            "    # Strict allowlist: only digits are permitted\n"
            "    if not re.fullmatch(r'\\d+', str(user_id)):\n"
            "        raise ValueError('user_id must be a numeric identifier')\n"
            "    conn = sqlite3.connect('app.db')\n"
            "    cursor = conn.cursor()\n"
            "    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
            "    return cursor.fetchone()\n"
        )
        return (
            modified,
            "Adds an input validation layer that rejects any user_id not matching "
            "a strict numeric allowlist before it reaches the query. Uses "
            "parameterized query as a second layer of defense.",
            "Blocks injection payloads at the input boundary; parameterized query "
            "provides defense-in-depth if validation is bypassed.",
            False,
        )

    elif strategy == "output_encoding":
        return (
            "# NOT APPLICABLE\n"
            "# Output encoding (HTML entity escaping, URL encoding, etc.) protects\n"
            "# against Cross-Site Scripting (XSS) by sanitizing data before it is\n"
            "# rendered in a browser. It does NOT prevent SQL injection, which occurs\n"
            "# at the database query layer, not the output layer.\n"
            "#\n"
            "# For SQL injection, use parameterized queries, stored procedures, or\n"
            "# strict input validation instead.\n"
            f"# Original vulnerable code: {code[:120]}\n",
            "Output encoding is not applicable to SQL injection. Encoding output "
            "data for safe browser rendering does not affect how user input is "
            "interpreted by the SQL query engine.",
            "No security improvement for SQL injection. Output encoding addresses "
            "XSS, not injection into database queries.",
            True,
        )

    elif strategy == "allowlist":
        modified = (
            "import re\n"
            "\n"
            "ALLOWED_COLUMNS = {'id', 'username', 'email', 'role'}\n"
            "\n"
            "def get_user(user_id, column='id'):\n"
            "    # Allowlist: only pre-approved column names may appear in the query\n"
            "    if column not in ALLOWED_COLUMNS:\n"
            "        raise ValueError(f'Column {column!r} is not in the allowed set')\n"
            "    # Validate user_id is numeric\n"
            "    if not re.fullmatch(r'\\d+', str(user_id)):\n"
            "        raise ValueError('user_id must be numeric')\n"
            "    conn = sqlite3.connect('app.db')\n"
            "    cursor = conn.cursor()\n"
            "    # Column name is validated against allowlist, user_id is parameterized\n"
            "    query = f'SELECT {column} FROM users WHERE id = ?'\n"
            "    cursor.execute(query, (user_id,))\n"
            "    return cursor.fetchone()\n"
        )
        return (
            modified,
            "Enforces an allowlist of permitted column names checked against a "
            "static set before query construction. Column values from the allowlist "
            "cannot contain SQL metacharacters. User data is still parameterized.",
            "Prevents column-name injection and data-value injection by combining "
            "an allowlist for identifiers with parameterized queries for values.",
            False,
        )

    elif strategy == "framework_protection":
        modified = (
            "# Use ORM / framework query builder instead of raw SQL\n"
            "# Example with SQLAlchemy Core (adapt to your framework):\n"
            "#\n"
            "# from sqlalchemy import create_engine, text\n"
            "# engine = create_engine('sqlite:///app.db')\n"
            "#\n"
            "def get_user(user_id):\n"
            "    # The ORM/framework query builder parameterizes automatically.\n"
            "    # Never construct raw SQL with user-supplied values.\n"
            "    from sqlalchemy import create_engine, text\n"
            "    engine = create_engine('sqlite:///app.db')\n"
            "    with engine.connect() as conn:\n"
            "        result = conn.execute(\n"
            "            text('SELECT * FROM users WHERE id = :uid'),\n"
            "            {'uid': user_id}\n"
            "        )\n"
            "        return result.fetchone()\n"
        )
        return (
            modified,
            "Delegates query construction to the framework's database abstraction "
            "(SQLAlchemy Core with named parameter binding). The framework handles "
            "escaping and parameterization internally, eliminating manual SQL "
            "string construction.",
            "Removes the root cause of injection by eliminating raw SQL string "
            "concatenation in application code, using the framework's safe query API.",
            False,
        )

    return (
        f"# Patch candidate using {strategy}\n{code}",
        f"Generic fallback for {strategy}.",
        f"Apply {strategy} to reduce SQL injection risk.",
        False,
    )


def _xss_fix(code: str, strategy: str) -> Tuple[str, str, str, bool]:
    if strategy == "output_encoding":
        modified = (
            "import html\n"
            "\n"
            "def render_comment(comment):\n"
            "    element = document.getElementById('output')\n"
            "    safe_output = html.escape(str(comment))\n"
            "    element.innerHTML = safe_output\n"
        )
        return (
            modified,
            "Applies HTML entity encoding to user-supplied content before assigning "
            "it to innerHTML, converting <, >, &, \", and ' to their safe entity "
            "equivalents.",
            "Prevents XSS by ensuring browser treats all user content as text, not "
            "executable HTML/JS.",
            False,
        )
    elif strategy == "framework_protection":
        modified = (
            "# Use framework template auto-escaping (e.g., React JSX, Jinja2, Angular)\n"
            "# React example -- JSX escapes by default:\n"
            "def render_comment(comment):\n"
            "    # React: {comment} is auto-escaped, never use dangerouslySetInnerHTML\n"
            "    return comment  # Framework renders safely via template binding\n"
        )
        return (
            modified,
            "Relies on the framework's built-in template auto-escaping (React JSX, "
            "Jinja2, Angular) to prevent XSS. Content is escaped at render time "
            "without manual encoding calls.",
            "Delegates XSS escaping to the framework, reducing risk of developer "
            "error in manual encoding.",
            False,
        )
    return (
        f"# Patch candidate: {strategy}\n{code}",
        f"Generic fallback for {strategy}.",
        f"Apply {strategy} to reduce XSS risk.",
        False,
    )


def _secret_fix(code: str, strategy: str) -> Tuple[str, str, str, bool]:
    if strategy == "allowlist":
        modified = (
            "# Environment variable approach -- no secrets in source code\n"
            "import os\n"
            "\n"
            "ALLOWED_SERVICES = {'auth-api', 'payment-api', 'analytics-api'}\n"
            "\n"
            "def get_service_client(service_name):\n"
            "    if service_name not in ALLOWED_SERVICES:\n"
            "        raise ValueError(f'Service {service_name!r} is not permitted')\n"
            "    api_key = os.environ.get(f'{service_name.upper().replace(\"-\", \"_\")}_KEY')\n"
            "    if not api_key:\n"
            "        raise RuntimeError(f'Missing API key for {service_name}')\n"
            "    return api_key\n"
        )
        return (
            modified,
            "Combines an allowlist of permitted service names with environment "
            "variable lookup for credentials. Secrets are never stored in source.",
            "Prevents credential leakage and restricts which services can be "
            "accessed, reducing blast radius if credentials are compromised.",
            False,
        )
    return (
        f"# Patch candidate: {strategy}\n{code}",
        f"Generic fallback for {strategy}.",
        f"Apply {strategy} to reduce secret exposure.",
        False,
    )


def _command_injection_fix(code: str, strategy: str) -> Tuple[str, str, str, bool]:
    if strategy == "parameterized_query":
        modified = (
            "import subprocess\n"
            "\n"
            "def run_command(cmd, args):\n"
            "    # Use subprocess with a list -- no shell interpretation\n"
            "    result = subprocess.run(\n"
            "        [cmd] + args,\n"
            "        shell=False,\n"
            "        capture_output=True,\n"
            "        text=True,\n"
            "    )\n"
            "    return result.stdout\n"
        )
        return (
            modified,
            "Replaces shell-based command execution with subprocess.run using a "
            "list of arguments and shell=False, preventing shell metacharacter "
            "injection.",
            "Eliminates command injection by bypassing the shell entirely; "
            "arguments are passed directly to the executable.",
            False,
        )
    return (
        f"# Patch candidate: {strategy}\n{code}",
        f"Generic fallback for {strategy}.",
        f"Apply {strategy} to reduce command injection risk.",
        False,
    )


def _path_traversal_fix(code: str, strategy: str) -> Tuple[str, str, str, bool]:
    if strategy == "allowlist":
        modified = (
            "import os\n"
            "\n"
            "ALLOWED_DIR = '/var/app/uploads'\n"
            "\n"
            "def read_file(user_path):\n"
            "    resolved = os.path.abspath(os.path.join(ALLOWED_DIR, user_path))\n"
            "    if not resolved.startswith(os.path.abspath(ALLOWED_DIR)):\n"
            "        raise ValueError('Path traversal detected: path escapes allowed directory')\n"
            "    with open(resolved, 'r') as f:\n"
            "        return f.read()\n"
        )
        return (
            modified,
            "Resolves the user-supplied path to an absolute path and verifies it "
            "remains within the allowed directory, preventing ../ traversal.",
            "Blocks path traversal by ensuring resolved path never escapes the "
            "intended base directory.",
            False,
        )
    return (
        f"# Patch candidate: {strategy}\n{code}",
        f"Generic fallback for {strategy}.",
        f"Apply {strategy} to reduce path traversal risk.",
        False,
    )


def _generic_fix(code: str, strategy: str) -> Tuple[str, str, str, bool]:
    return (
        f"# Patch candidate using {strategy}\n# Review and adapt to specific context\n{code}",
        f"Generic fallback for {strategy}.",
        f"Apply {strategy} to reduce vulnerability risk.",
        False,
    )


class PatchGenerationAgent:
    """
    Multi-Candidate Patch Generation Agent.

    Generates exactly 5 candidate patches per vulnerability finding.
    Each candidate is a suggestion only -- never a claim of security.

    Pipeline:
    1. Build structured prompt from vulnerability + source code
    2. Query LLM for patch candidates
    3. Validate JSON structure of response
    4. Retry on malformed responses (up to MAX_RETRIES)
    5. Fall back to deterministic generation if LLM unavailable
    6. Store all candidates in PostgreSQL
    7. Return PatchGenerationResponse
    """

    def generate_patches(
        self,
        request: PatchGenerationRequest,
    ) -> PatchGenerationResponse:
        """
        Generate 5 candidate patches for a vulnerability.

        Args:
            request: PatchGenerationRequest with vulnerability details and source code

        Returns:
            PatchGenerationResponse with exactly 5 candidate patches
        """
        logger.info(
            f"[PatchGen] Generating patches for vulnerability {request.vulnerability_id} "
            f"({request.vulnerability_type} at {request.file}:{request.line})"
        )
        start_time = time.time()
        total_retries = 0
        model_used = settings.default_llm_model
        candidates: List[PatchCandidate] = []

        # Try LLM with retry handling
        prompt = _build_prompt(request)

        for attempt in range(MAX_RETRIES):
            raw_text, retries = _query_llm(prompt, attempt)
            total_retries += retries

            if not raw_text:
                logger.info(f"[PatchGen] LLM unavailable, using fallback generation (attempt {attempt + 1})")
                break

            try:
                candidates = _parse_llm_response(raw_text)
                if len(candidates) >= NUM_CANDIDATES:
                    candidates = candidates[:NUM_CANDIDATES]
                    logger.info(f"[PatchGen] Successfully parsed {len(candidates)} candidates from LLM")
                    break
                else:
                    logger.warning(
                        f"[PatchGen] LLM returned {len(candidates)} candidates, "
                        f"expected {NUM_CANDIDATES}. Retrying ({attempt + 1}/{MAX_RETRIES})"
                    )
                    candidates = []
                    total_retries += 1
            except (json.JSONDecodeError, ValueError) as e:
                logger.warning(
                    f"[PatchGen] Malformed LLM response (attempt {attempt + 1}/{MAX_RETRIES}): {e}"
                )
                candidates = []
                total_retries += 1

        # Fallback if LLM failed or returned invalid data
        if len(candidates) < NUM_CANDIDATES:
            logger.info("[PatchGen] Using deterministic fallback patch generation")
            model_used = "deterministic-fallback"
            candidates = _generate_fallback_candidates(request)

        # Ensure exactly NUM_CANDIDATES
        candidates = candidates[:NUM_CANDIDATES]

        # Pad with fallback if somehow still short
        if len(candidates) < NUM_CANDIDATES:
            fallback = _generate_fallback_candidates(request)
            for c in fallback:
                if len(candidates) >= NUM_CANDIDATES:
                    break
                if not any(existing.patch_id == c.patch_id for existing in candidates):
                    candidates.append(c)
            candidates = candidates[:NUM_CANDIDATES]

        duration_ms = int((time.time() - start_time) * 1000)

        # Store in PostgreSQL (non-blocking, with fallback)
        try:
            import asyncio
            try:
                loop = asyncio.get_running_loop()
                # We're inside an async context, schedule as task
                asyncio.ensure_future(
                    store_patch_candidates(
                        vulnerability_id=request.vulnerability_id,
                        candidates=candidates,
                        model_used=model_used,
                    )
                )
            except RuntimeError:
                # No running loop, create one
                asyncio.run(
                    store_patch_candidates(
                        vulnerability_id=request.vulnerability_id,
                        candidates=candidates,
                        model_used=model_used,
                    )
                )
        except Exception as e:
            logger.warning(f"[PatchGen] Could not store patches to DB: {e}")

        logger.info(
            f"[PatchGen] Generated {len(candidates)} candidates for {request.vulnerability_id} "
            f"in {duration_ms}ms (retries: {total_retries}, model: {model_used})"
        )

        return PatchGenerationResponse(
            vulnerability_id=request.vulnerability_id,
            candidates=candidates,
            generation_duration_ms=duration_ms,
            model_used=model_used,
            retry_count=total_retries,
        )
