# 15 - Security Analysis

## Overview

The Security Analysis Agent performs static security analysis using Semgrep to detect common vulnerability patterns.

## Detection Categories

| Category | CWE | Description |
|----------|-----|-------------|
| SQL Injection | CWE-89 | Unsanitized input in SQL queries |
| Cross-Site Scripting | CWE-79 | Unescaped output in HTML/JS |
| Hardcoded Secrets | CWE-798 | Passwords, API keys in source |
| Command Injection | CWE-78 | Unsanitized input in shell commands |
| Path Traversal | CWE-22 | Unvalidated file paths |
| Insecure JWT | CWE-347 | Weak JWT validation |

## Detection Strategy

### Semgrep Integration

The agent runs Semgrep rules against source files:

1. Scan workspace directory for source files
2. Apply Semgrep rules (custom + community)
3. Parse findings into structured format
4. Map to CWE classifications
5. Normalize severity levels

### Rule Categories

**Custom Rules** (`ai-engine/app/rules/`):
- `python/security/` - Python-specific security rules
- `javascript/security/` - JavaScript/TypeScript rules
- `java/security/` - Java security rules

**Community Rules**:
- Semgrep registry rules for OWASP Top 10
- Language-specific security patterns

### Severity Mapping

| Semgrep Severity | HalluciShield Severity |
|------------------|----------------------|
| ERROR | HIGH |
| WARNING | MEDIUM |
| INFO | LOW |

## API Endpoint

```
POST /api/v1/security/scan
```

**Request**:
```json
{
  "repository_id": "uuid",
  "workspace_path": "/workspace/runs/<scanId>",
  "scan_rules": ["sql_injection", "xss", "hardcoded_secrets"]
}
```

**Response** (`SecurityAnalysisResponse`):
```json
{
  "repository_id": "uuid",
  "findings": [
    {
      "rule_id": "python.security.audit.django.sql-injection",
      "type": "SQL Injection",
      "severity": "HIGH",
      "file_path": "src/db.py",
      "start_line": 42,
      "end_line": 42,
      "description": "Unsanitized input used in SQL query",
      "cwe": "CWE-89",
      "raw_details": {}
    }
  ],
  "total_findings": 1,
  "scan_duration_ms": 800
}
```

## Security

- `validate_workspace_path()` called before file walking
- Only scans files within allowed workspace root
- Semgrep runs with restricted permissions

## Test Coverage

`ai-engine/tests/test_security_agent.py`:
- SQL injection detection
- XSS detection
- Hardcoded secrets detection
- Command injection detection
- Path traversal detection
- Multiple vulnerability types
- Clean code (no false positives)
