# 19 - Validation Sandbox

## Overview

The Validation Sandbox executes candidate patches in an isolated Docker container to verify correctness and safety.

## Sandbox Architecture

```
┌─────────────────────────────────────┐
│  Docker Container (Python 3.11-slim)│
│                                     │
│  /sandbox/runner.py                 │
│  /workspace/ (bind-mounted)         │
│    ├── patch.py                     │
│    ├── target_file                  │
│    ├── original_code                │
│    ├── language                     │
│    ├── compile_cmd                  │
│    ├── test_cmd                     │
│    ├── scan_cmd                     │
│    └── results.json                 │
│                                     │
│  USER: sandboxuser (UID 10001)      │
│  NO ROOT ACCESS                     │
└─────────────────────────────────────┘
```

## Validation Pipeline

### 1. Repository Preparation

Read configuration files:
- `language`: Target language (python/javascript/java)
- `compile_cmd`: Compilation command (if applicable)
- `test_cmd`: Test execution command
- `scan_cmd`: Security scan command

### 2. Patch Application

1. Validate target path stays within workspace (path traversal prevention)
2. Write original code (if provided)
3. Apply patch code to target file
4. Verify file written successfully

### 3. Compilation

Run compilation command (if provided):
- Python: `python -m py_compile <file>`
- JavaScript: `node --check <file>`
- Java: `javac <file>`

### 4. Test Execution

Run test suite and parse results:
- pytest output parsing
- jest output parsing
- junit output parsing
- Capture pass/fail/skip counts

### 5. Security Scan

Run security scanner (Semgrep):
- Parse JSON output
- Count vulnerabilities found
- Return structured findings

### 6. Performance Measurement

Collect runtime metrics:
- Execution time
- Memory peak (from `/proc/self/status`)
- CPU usage

### 7. Result Collection

Write structured JSON to `results.json`:
```json
{
  "language": "python",
  "patch_application": { "success": true },
  "compilation": { "success": true },
  "tests": {
    "framework": "pytest",
    "total_tests": 15,
    "passed": 14,
    "failed": 1,
    "skipped": 0
  },
  "security_scan": {
    "scanner": "semgrep",
    "vulnerabilities_found": 0
  },
  "performance": {
    "memory_peak_mb": 45.2
  },
  "execution_time": 12500
}
```

## Security Measures

| Measure | Implementation |
|---------|---------------|
| Non-root user | `sandboxuser` (UID 10001) |
| Path traversal | Target path validation in `apply_patch()` |
| Network isolation | Container has no network access |
| Resource limits | 30s timeout per command |
| File size limits | 10KB output truncation |

## API Endpoint

```
POST /api/v1/vulnerabilities/{id}/validate-patch
```

Triggers sandbox validation and returns results.

## Docker Configuration

```dockerfile
FROM python:3.11-slim
RUN useradd -m -u 10001 sandboxuser
WORKDIR /sandbox
COPY runner.py /sandbox/runner.py
USER sandboxuser
CMD ["python", "runner.py"]
```

## Test Coverage

- Patch application success/failure
- Path traversal rejection
- Compilation pass/fail
- Test execution parsing
- Security scan results
- Timeout handling
