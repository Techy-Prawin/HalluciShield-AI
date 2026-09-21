# 10 - AI Engine API

## Overview

FastAPI service running on port 8000. Provides analysis endpoints for hallucination detection, security scanning, dependency validation, risk assessment, and more.

Entry point: `ai-engine/app/main.py`

## Middleware

1. **CORS** - Configurable origins (default: `http://localhost:3000`)
2. **RateLimitMiddleware** - 120 requests/minute per client IP
3. **SecurityHeadersMiddleware** - X-Content-Type-Options, X-Frame-Options, etc.

## Core Endpoints

### Health Check

```
GET /api/v1/health
```

Returns service status, LLM provider connectivity, model info.

### Hallucination Detection

```
POST /api/v1/hallucination/detect
```

**Request**:
```json
{
  "repository_id": "uuid",
  "workspace_path": "/workspace/runs/<scanId>"
}
```

**Response**: `DetectionResponse` with hallucination findings (phantom methods, invalid imports, context drift).

### Security Analysis

```
POST /api/v1/security/scan
```

**Request**:
```json
{
  "repository_id": "uuid",
  "workspace_path": "/workspace/runs/<scanId>",
  "scan_rules": ["sql_injection", "xss"]
}
```

**Response**: `SecurityAnalysisResponse` with vulnerability findings (CWE-mapped).

### Dependency Analysis

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

**Response**: `DependencyAnalysisResponse` with dependency vulnerabilities.

### Risk Assessment

```
GET  /api/v1/risk/repositories/{id}/risk?workspace_path=...
POST /api/v1/risk/assess
```

Runs all three agents (hallucination, security, dependency) and returns a combined risk assessment.

## Additional Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /api/v1/analyzer/analyze` | Code analysis via RepositoryAnalyzer |
| `POST /api/v1/vulnerabilities/{id}/generate-patches` | Generate patches for a vulnerability |
| `POST /api/v1/vulnerabilities/{id}/validate-patch` | Validate a patch in sandbox |
| `POST /api/v1/vulnerabilities/{id}/validate-candidates` | Validate multiple patch candidates |
| `POST /api/v1/vulnerabilities/{id}/rank-patches` | Rank patches by confidence |
| `GET  /api/v1/vulnerabilities/{id}/recommendation` | Get patch recommendation |
| `GET  /api/v1/vulnerabilities/{id}/patches/{pid}/explanation` | Get patch explanation |
| `POST /api/v1/vulnerabilities/{id}/patches/{pid}/review` | Review a patch |
| `POST /api/v1/vulnerabilities/{id}/patches/{pid}/approve` | Approve a patch |
| `POST /api/v1/vulnerabilities/{id}/patches/{pid}/reject` | Reject a patch |
| `GET  /api/v1/vulnerabilities/{id}/patches/{pid}/approval-status` | Get approval status |
| `GET  /api/v1/vulnerabilities/{id}/approvals` | Approval history |
| `GET  /api/v1/dashboard/risk` | Risk dashboard data |
| `GET  /api/v1/dashboard/approval` | Approval dashboard |
| `GET  /api/v1/dashboard/recommendation` | Recommendation dashboard |
| `GET  /api/v1/dashboard/explanation` | Explanation dashboard |
| `GET  /api/v1/dashboard/monitoring` | Monitoring dashboard |
| `POST /api/v1/monitoring/events` | Record runtime events |
| `GET  /api/v1/monitoring/alerts` | Get monitoring alerts |
| `POST /api/v1/monitoring/simulate` | Simulate monitoring events |
| `POST /api/v1/learning/feedback` | Submit learning feedback |
| `GET  /api/v1/learning/weights` | Get current ACE weights |
| `POST /api/v1/experiments/compare` | Compare experiment results |
| `GET  /api/v1/analytics/summary` | Analytics summary |

## Security

Every analysis endpoint calls `validate_workspace_path()` before file access:
- Rejects path traversal (`..`)
- When `HALLUCISHIELD_WORKSPACE_ROOT` is set, enforces paths are inside root
- Optional `require_api_key()` for `X-API-Key` header validation

## File Structure

```
ai-engine/app/
├── main.py                   # FastAPI app setup
├── config.py                 # Settings (pydantic-settings)
├── security.py               # Security utilities
├── security_utils.py         # Additional security helpers
├── api/                      # Route modules (14 routers)
│   ├── health.py
│   ├── hallucination.py
│   ├── security.py
│   ├── dependency.py
│   ├── risk.py
│   ├── analyzer.py
│   ├── dashboard.py
│   ├── patches.py
│   ├── recommendation.py
│   ├── patch_approval.py
│   ├── monitoring.py
│   ├── learning.py
│   ├── experiments.py
│   └── analytics.py
├── agents/                   # Agent implementations
│   ├── hallucination_agent.py
│   ├── security_agent.py
│   ├── dependency_agent.py
│   ├── risk_engine.py
│   ├── patch_agent.py
│   ├── validation_agent.py
│   ├── confidence_engine.py
│   ├── patch_ranker.py
│   └── ...
└── analyzer/                 # Code analysis engine
    ├── engine.py
    ├── models.py
    └── *_parser.py           # Language-specific parsers
```
