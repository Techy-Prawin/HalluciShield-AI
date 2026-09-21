# 16 - Dependency Analysis

## Overview

The Dependency Analysis Agent validates project dependencies against public package registries to detect phantom packages, outdated versions, and known vulnerabilities.

## Analysis Strategy

### Package Registry Validation

1. Parse dependency files (`requirements.txt`, `package.json`, `pom.xml`, etc.)
2. For each dependency:
   - Check existence on PyPI/npm/Maven Central
   - Verify version availability
   - Check for known vulnerabilities (when available)
3. Flag non-existent or suspicious packages

### Supported Languages

| Language | Dependency File | Registry |
|----------|----------------|----------|
| Python | `requirements.txt`, `setup.py`, `pyproject.toml` | PyPI |
| JavaScript | `package.json` | npm |
| Java | `pom.xml`, `build.gradle` | Maven Central |

### Detection Categories

- **Phantom Package**: Package doesn't exist on registry
- **Version Mismatch**: Requested version not available
- **Deprecated Package**: Package marked as deprecated
- **Known Vulnerability**: Package has known security issues

## API Endpoint

```
POST /api/v1/dependency/analyze
```

**Request**:
```json
{
  "repository_id": "uuid",
  "workspace_path": "/workspace/runs/<scanId>"
}
```

**Response** (`DependencyAnalysisResponse`):
```json
{
  "repository_id": "uuid",
  "dependencies": [
    {
      "name": "requests",
      "version": "2.31.0",
      "registry": "pypi",
      "exists": true,
      "latest_version": "2.32.0",
      "deprecated": false,
      "vulnerabilities": []
    },
    {
      "name": "nonexistent-pkg",
      "version": "1.0.0",
      "registry": "pypi",
      "exists": false,
      "latest_version": null,
      "deprecated": false,
      "vulnerabilities": []
    }
  ],
  "total_dependencies": 15,
  "phantom_packages": 1,
  "analysis_duration_ms": 2500
}
```

## Security

- `validate_workspace_path()` called before file access
- HTTP requests to registries use `httpx` with timeout
- SSRF protection via `validate_url_safe()`

## Performance

- Registry lookups are HTTP-based (not cached)
- Each dependency requires one HTTP request
- Consider caching for production use

## Test Coverage

`ai-engine/tests/test_dependency_agent.py`:
- Phantom package detection
- Valid package verification
- Version checking
- Multiple dependency files
- Network error handling
