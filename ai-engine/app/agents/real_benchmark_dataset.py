"""
Real benchmark dataset for HalluciShield research experiments.

9 controlled test cases, one per vulnerability category.
Each test case contains genuinely vulnerable code that the real pipeline agents
can process and detect using their actual detection logic.

Dataset version: v1.0-real
"""

from app.agents.models import TestCase, VulnerabilityTestCategory

REAL_BENCHMARK_VERSION = "v1.0-real"

REAL_BENCHMARK_CASES = [
    # ----------------------------------------------------------------
    # 1. SQL Injection — string concatenation in query
    # ----------------------------------------------------------------
    TestCase(
        test_id="R-SQL-001",
        vuln_category=VulnerabilityTestCategory.SQL_INJECTION,
        vulnerability_type="SQL_INJECTION",
        severity="CRITICAL",
        file_path="app/db.py",
        original_code=(
            'def get_user(user_id):\n'
            '    conn = sqlite3.connect("app.db")\n'
            '    cursor = conn.cursor()\n'
            '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'
            '    return cursor.fetchone()\n'
        ),
        vulnerable_line=4,
        description="SQL injection via string concatenation in SELECT query",
        cwe="CWE-89",
        expected_detection=True,
        expected_patch_types=["parameterized_query", "input_validation"],
    ),

    # ----------------------------------------------------------------
    # 2. XSS — innerHTML assignment
    # ----------------------------------------------------------------
    TestCase(
        test_id="R-XSS-001",
        vuln_category=VulnerabilityTestCategory.XSS,
        vulnerability_type="CROSS_SITE_SCRIPTING",
        severity="HIGH",
        file_path="app/templates.py",
        original_code=(
            'def render_comment(comment):\n'
            '    element = document.getElementById("output")\n'
            '    element.innerHTML = comment\n'
        ),
        vulnerable_line=3,
        description="DOM XSS via innerHTML with unescaped user input",
        cwe="CWE-79",
        expected_detection=True,
        expected_patch_types=["output_encoding", "framework_protection"],
    ),

    # ----------------------------------------------------------------
    # 3. Hardcoded Secret — password literal
    # ----------------------------------------------------------------
    TestCase(
        test_id="R-SECRET-001",
        vuln_category=VulnerabilityTestCategory.HARDCODED_SECRETS,
        vulnerability_type="HARDCODED_SECRET",
        severity="CRITICAL",
        file_path="app/config.py",
        original_code=(
            'DATABASE_PASSWORD = "super_secret_123"\n'
            'API_KEY = "sk-abc123def456ghi789"\n'
            '\n'
            'def connect_db():\n'
            '    return db.connect(password=DATABASE_PASSWORD)\n'
        ),
        vulnerable_line=1,
        description="Hardcoded database password and API key in source code",
        cwe="CWE-798",
        expected_detection=True,
        expected_patch_types=["environment_variable", "secrets_manager"],
    ),

    # ----------------------------------------------------------------
    # 4. Command Injection — os.system()
    # ----------------------------------------------------------------
    TestCase(
        test_id="R-CMD-001",
        vuln_category=VulnerabilityTestCategory.COMMAND_INJECTION,
        vulnerability_type="COMMAND_INJECTION",
        severity="CRITICAL",
        file_path="app/utils.py",
        original_code=(
            'import os\n'
            '\n'
            'def ping_host(hostname):\n'
            '    result = os.system("ping -c 1 " + hostname)\n'
            '    return result\n'
        ),
        vulnerable_line=4,
        description="Command injection via os.system with user-supplied hostname",
        cwe="CWE-78",
        expected_detection=True,
        expected_patch_types=["subprocess_safe", "input_validation"],
    ),

    # ----------------------------------------------------------------
    # 5. Path Traversal — open() with concatenation
    # ----------------------------------------------------------------
    TestCase(
        test_id="R-PATH-001",
        vuln_category=VulnerabilityTestCategory.PATH_TRAVERSAL,
        vulnerability_type="PATH_TRAVERSAL",
        severity="HIGH",
        file_path="app/files.py",
        original_code=(
            'def read_user_file(filename):\n'
            '    filepath = "/var/uploads/" + filename\n'
            '    with open(filepath, "r") as f:\n'
            '        return f.read()\n'
        ),
        vulnerable_line=2,
        description="Path traversal via unsanitized filename in open()",
        cwe="CWE-22",
        expected_detection=True,
        expected_patch_types=["path_validation", "allowlist"],
    ),

    # ----------------------------------------------------------------
    # 6. Insecure JWT — algorithm none
    # ----------------------------------------------------------------
    TestCase(
        test_id="R-JWT-001",
        vuln_category=VulnerabilityTestCategory.INSECURE_JWT,
        vulnerability_type="INSECURE_JWT",
        severity="HIGH",
        file_path="app/auth.py",
        original_code=(
            'import jwt\n'
            '\n'
            'def decode_token(token):\n'
            '    payload = jwt.decode(token, algorithms=["none"])\n'
            '    return payload\n'
        ),
        vulnerable_line=4,
        description="Insecure JWT decoding with none algorithm allowed",
        cwe="CWE-327",
        expected_detection=True,
        expected_patch_types=["secure_algorithm", "key_validation"],
    ),

    # ----------------------------------------------------------------
    # 7. Authentication Flaw — no brute-force protection
    # ----------------------------------------------------------------
    TestCase(
        test_id="R-AUTH-001",
        vuln_category=VulnerabilityTestCategory.AUTH_FLAW,
        vulnerability_type="AUTHENTICATION_FLAW",
        severity="HIGH",
        file_path="app/login.py",
        original_code=(
            'def login(username, password):\n'
            '    user = db.query("SELECT * FROM users WHERE username = ?", username)\n'
            '    if user and user.password == password:\n'
            '        return create_session(user)\n'
            '    return None\n'
        ),
        vulnerable_line=3,
        description="Plaintext password comparison without rate limiting or account lockout",
        cwe="CWE-307",
        expected_detection=False,
        expected_patch_types=["hash_comparison", "rate_limiting"],
    ),

    # ----------------------------------------------------------------
    # 8. Hallucinated API — non-existent package import
    # ----------------------------------------------------------------
    TestCase(
        test_id="R-HAPI-001",
        vuln_category=VulnerabilityTestCategory.HALLUCINATED_API,
        vulnerability_type="HALLUCINATED_API",
        severity="MEDIUM",
        file_path="app/services.py",
        original_code=(
            'from quantum_blockchain import QuantumEncryptor\n'
            '\n'
            'def encrypt_data(data):\n'
            '    qe = QuantumEncryptor()\n'
            '    return qe.encrypt(data)\n'
        ),
        vulnerable_line=1,
        description="Import from non-existent package quantum_blockchain",
        cwe="N/A",
        expected_detection=False,
        expected_patch_types=["remove_dependency"],
    ),

    # ----------------------------------------------------------------
    # 9. Hallucinated Package — fake dependency
    # ----------------------------------------------------------------
    TestCase(
        test_id="R-HPKG-001",
        vuln_category=VulnerabilityTestCategory.HALLUCINATED_PACKAGE,
        vulnerability_type="HALLUCINATED_PACKAGE",
        severity="MEDIUM",
        file_path="requirements.txt",
        original_code=(
            'flask==2.3.2\n'
            'requests==2.31.0\n'
            'neural-style-transfer==0.0.1\n'
            'quantum-crypto==1.0.0\n'
        ),
        vulnerable_line=3,
        description="Fake packages neural-style-transfer and quantum-crypto in requirements.txt",
        cwe="N/A",
        expected_detection=False,
        expected_patch_types=["remove_dependency"],
    ),
]

REAL_BENCHMARK_BY_ID = {tc.test_id: tc for tc in REAL_BENCHMARK_CASES}
REAL_BENCHMARK_BY_CATEGORY = {}
for tc in REAL_BENCHMARK_CASES:
    REAL_BENCHMARK_BY_CATEGORY.setdefault(tc.vuln_category.value, []).append(tc)
