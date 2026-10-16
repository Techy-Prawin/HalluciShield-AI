"""
Unit and Integration Tests for Java Security Scanner Coverage.

Verifies:
1. Java SQL injection → detected
2. Java command injection → detected
3. Java path traversal → detected
4. Java XXE → detected
5. Java insecure deserialization → detected
6. Java clean sample → no false positive
7. Java scanner failure/timeout → explicit failure status (never masked as clean)
8. Existing Python/JS behavior remains unchanged
9. Deterministic Java fallback scanner functions independently when Semgrep is unavailable
"""

import os
import shutil
import tempfile
import pytest
from unittest.mock import patch, MagicMock

from app.agents.models import VulnerabilityType, VulnerabilitySeverity, SecurityFinding
from app.agents.security_agent import SecurityAnalysisAgent
from app.agents.semgrep_runner import SemgrepRunner, semgrep_runner


# --- Small Controlled Fixtures (NO benchmark ground-truth leakage) ---

JAVA_SQL_INJECTION = """
package com.example.dao;

import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;

public class UserDao {
    public void getUser(Connection conn, String userId) throws Exception {
        Statement stmt = conn.createStatement();
        // Unsafe SQL query concatenation
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        ResultSet rs = stmt.executeQuery(query);
    }
}
"""

JAVA_COMMAND_INJECTION = """
package com.example.service;

public class SystemService {
    public void executeCommand(String command) throws Exception {
        // Command injection vulnerability via Runtime.exec
        Runtime.getRuntime().exec("ping " + command);
    }
}
"""

JAVA_PATH_TRAVERSAL = """
package com.example.controller;

import java.io.File;
import javax.servlet.http.HttpServletRequest;

public class FileController {
    public File getFile(HttpServletRequest request) {
        String filename = request.getParameter("filename");
        // Path traversal vulnerability
        File file = new File("/var/data/uploads", filename);
        return file;
    }
}
"""

JAVA_XXE = """
package com.example.xml;

import javax.xml.parsers.DocumentBuilderFactory;

public class XmlParser {
    public void parseXml(java.io.InputStream stream) throws Exception {
        // XXE vulnerability - XML parser without entity restriction
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder().parse(stream);
    }
}
"""

JAVA_DESERIALIZATION = """
package com.example.serialize;

import java.io.ObjectInputStream;
import java.io.InputStream;

public class Deserializer {
    public Object deserializeData(InputStream in) throws Exception {
        // Insecure deserialization via ObjectInputStream.readObject
        ObjectInputStream ois = new ObjectInputStream(in);
        return ois.readObject();
    }
}
"""

JAVA_CLEAN_SAMPLE = """
package com.example.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class SafeUserDao {
    public String getUserName(Connection conn, String userId) throws Exception {
        // Safe parameterized query
        String sql = "SELECT name FROM users WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("name");
                }
            }
        }
        return null;
    }
}
"""

PYTHON_VULNERABLE = """
import os

def run_task(user_input):
    # Command injection
    os.system("echo " + user_input)
"""

JS_VULNERABLE = """
function displayUser(input) {
    // XSS vulnerability
    document.getElementById("profile").innerHTML = input;
}
"""


@pytest.fixture
def make_temp_repo():
    created_dirs = []

    def _maker(filename: str, content: str) -> str:
        d = tempfile.mkdtemp(prefix="test_sec_java_")
        created_dirs.append(d)
        fpath = os.path.join(d, filename)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)
        return d

    yield _maker

    for d in created_dirs:
        shutil.rmtree(d, ignore_errors=True)


class TestJavaSecurityScanner:
    """Test suite for Java security vulnerability scanning."""

    def test_java_sql_injection_detected(self, make_temp_repo):
        """Verify Java SQL injection is genuinely detected with CWE-89."""
        repo_dir = make_temp_repo("UserDao.java", JAVA_SQL_INJECTION)
        agent = SecurityAnalysisAgent()
        response = agent.analyze_security("test-java-sqli", repo_dir)

        assert response.total_vulnerabilities > 0
        sqli_findings = [f for f in response.findings if f.type == VulnerabilityType.SQL_INJECTION or f.cwe == "CWE-89"]
        assert len(sqli_findings) > 0
        finding = sqli_findings[0]
        assert finding.cwe == "CWE-89"
        assert finding.evidence
        assert "UserDao.java" in finding.file

    def test_java_command_injection_detected(self, make_temp_repo):
        """Verify Java command injection is genuinely detected with CWE-78."""
        repo_dir = make_temp_repo("SystemService.java", JAVA_COMMAND_INJECTION)
        agent = SecurityAnalysisAgent()
        response = agent.analyze_security("test-java-cmdi", repo_dir)

        assert response.total_vulnerabilities > 0
        cmdi_findings = [f for f in response.findings if f.type == VulnerabilityType.COMMAND_INJECTION or f.cwe == "CWE-78"]
        assert len(cmdi_findings) > 0
        finding = cmdi_findings[0]
        assert finding.cwe == "CWE-78"
        assert finding.evidence
        assert "SystemService.java" in finding.file

    def test_java_path_traversal_detected(self, make_temp_repo):
        """Verify Java path traversal is genuinely detected with CWE-22."""
        repo_dir = make_temp_repo("FileController.java", JAVA_PATH_TRAVERSAL)
        agent = SecurityAnalysisAgent()
        response = agent.analyze_security("test-java-path", repo_dir)

        assert response.total_vulnerabilities > 0
        path_findings = [f for f in response.findings if f.type == VulnerabilityType.PATH_TRAVERSAL or f.cwe == "CWE-22"]
        assert len(path_findings) > 0
        finding = path_findings[0]
        assert finding.cwe == "CWE-22"
        assert finding.evidence
        assert "FileController.java" in finding.file

    def test_java_xxe_detected(self, make_temp_repo):
        """Verify Java XXE is genuinely detected."""
        repo_dir = make_temp_repo("XmlParser.java", JAVA_XXE)
        agent = SecurityAnalysisAgent()
        response = agent.analyze_security("test-java-xxe", repo_dir)

        assert response.total_vulnerabilities > 0
        xxe_findings = [f for f in response.findings if f.cwe == "CWE-611" or "xml" in f.rule_id.lower() or "xxe" in f.rule_id.lower()]
        assert len(xxe_findings) > 0
        assert xxe_findings[0].evidence

    def test_java_deserialization_detected(self, make_temp_repo):
        """Verify Java insecure deserialization is detected with CWE-502."""
        repo_dir = make_temp_repo("Deserializer.java", JAVA_DESERIALIZATION)
        agent = SecurityAnalysisAgent()
        response = agent.analyze_security("test-java-deserial", repo_dir)

        assert response.total_vulnerabilities > 0
        deserial_findings = [f for f in response.findings if f.cwe == "CWE-502" or f.type == VulnerabilityType.INSECURE_DESERIALIZATION or "deserial" in f.rule_id.lower()]
        assert len(deserial_findings) > 0
        assert deserial_findings[0].evidence

    def test_java_clean_sample_no_false_positive(self, make_temp_repo):
        """Verify clean Java sample does not trigger false positives."""
        repo_dir = make_temp_repo("SafeUserDao.java", JAVA_CLEAN_SAMPLE)
        agent = SecurityAnalysisAgent()
        response = agent.analyze_security("test-java-clean", repo_dir)

        assert response.total_vulnerabilities == 0
        assert len(response.findings) == 0

    def test_scanner_failure_not_masked_as_clean(self):
        """Verify scanner failure raises an exception and is never returned as clean."""
        agent = SecurityAnalysisAgent()
        with patch.object(
            agent.semgrep,
            "run_scan",
            return_value=([], {"status": "FAILED", "error": "Semgrep process crashed", "scanner": "semgrep"})
        ):
            with pytest.raises(RuntimeError) as exc_info:
                agent.analyze_security("test-crash", ".")
            assert "Security scanner FAILED" in str(exc_info.value)

    def test_scanner_timeout_not_masked_as_clean(self):
        """Verify scanner timeout raises an exception and is never returned as clean."""
        agent = SecurityAnalysisAgent()
        with patch.object(
            agent.semgrep,
            "run_scan",
            return_value=([], {"status": "TIMEOUT", "error": "Scan timed out after 120s", "scanner": "semgrep"})
        ):
            with pytest.raises(RuntimeError) as exc_info:
                agent.analyze_security("test-timeout", ".")
            assert "Security scanner TIMEOUT" in str(exc_info.value)

    def test_existing_languages_preserved(self, make_temp_repo):
        """Verify Python and JavaScript scanning still work normally."""
        py_repo = make_temp_repo("tasks.py", PYTHON_VULNERABLE)
        agent = SecurityAnalysisAgent()
        py_res = agent.analyze_security("test-py", py_repo)
        assert py_res.total_vulnerabilities > 0

        js_repo = make_temp_repo("app.js", JS_VULNERABLE)
        js_res = agent.analyze_security("test-js", js_repo)
        assert js_res.total_vulnerabilities > 0

    def test_deterministic_fallback_scanner_directly(self, make_temp_repo):
        """Verify fallback pattern scanner detects Java vulnerabilities when Semgrep is unavailable."""
        runner = SemgrepRunner()
        # Direct test on fallback scan
        repo_sqli = make_temp_repo("UserDao.java", JAVA_SQL_INJECTION)
        findings, meta = runner._fallback_scan(repo_sqli, 0.0)
        assert len(findings) > 0
        assert meta["status"] == "COMPLETED"
        assert meta["scanner"] == "fallback"

        repo_clean = make_temp_repo("SafeUserDao.java", JAVA_CLEAN_SAMPLE)
        clean_findings, _ = runner._fallback_scan(repo_clean, 0.0)
        assert len(clean_findings) == 0
