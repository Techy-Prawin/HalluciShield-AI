# 02 - System Architecture

## Service Topology

HalluciShield runs as four containerized services:

```
┌─────────────────────────────────────────────────────────────┐
│                     Docker Compose                          │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────┐   │
│  │  Frontend    │  │  Backend    │  │  AI Engine       │   │
│  │  Next.js     │──│  Express    │──│  FastAPI         │   │
│  │  :3000       │  │  :4000      │  │  :8000           │   │
│  └─────────────┘  └──────┬──────┘  └────────┬─────────┘   │
│                          │                   │              │
│                   ┌──────▼──────┐    ┌──────▼─────────┐   │
│                   │ PostgreSQL  │    │  Shared Volume  │   │
│                   │ :5432       │    │  /workspace     │   │
│                   └─────────────┘    └────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow

### Upload Flow
1. User drops a `.zip` archive into the frontend upload portal
2. Frontend POSTs to `POST /api/repositories/upload` on the backend
3. Backend stages the archive at `/workspace/archives/<repoId>.zip`
4. Backend extracts files into `/workspace/runs/<repoId>/`
5. Metadata stored in PostgreSQL `repositories` table
6. Response includes workspace path and file count

### Scan Flow
1. User triggers scan via `POST /api/orchestration/scan`
2. Backend generates scan ID, materializes workspace from staged archive
3. Backend calls AI engine endpoints in sequence:
   - `POST /api/v1/hallucination/detect`
   - `POST /api/v1/security/scan`
   - `POST /api/v1/dependency/analyze`
4. AI engine reads source files from shared workspace volume
5. Results aggregated into `RiskAssessment`
6. Scan status updated in database (PENDING → SCANNING → COMPLETED)
7. Managed workspace auto-cleaned after terminal state

### Agent Communication
- Backend → AI Engine: HTTP REST calls with `X-Request-ID` propagation
- AI Engine → LLM: Groq API (OpenAI-compatible) via `httpx`
- AI Engine → Shared Volume: Direct filesystem reads (no network transfer)

## Security Boundaries

| Boundary | Mechanism |
|----------|-----------|
| Zip-slip | `UploadService.safeExtractZip()` validates all paths before extraction |
| Path traversal | `validate_workspace_path()` rejects `..` components |
| Workspace isolation | AI engine restricted to `HALLUCISHIELD_WORKSPACE_ROOT` when configured |
| SSRF | `validate_url_safe()` blocks private IP ranges |
| Prompt injection | `sanitize_for_llm_prompt()` strips injection patterns |
| Rate limiting | 120 requests/minute per client |
| API key auth | Optional `X-API-Key` header validation |

## Request Tracing

Every request gets a UUID via `requestIdMiddleware`. The ID is:
- Generated server-side or honored from `X-Request-ID` header
- Stored in `res.locals.requestId`
- Echoed in `X-Request-ID` response header
- Logged on response finish with method, URL, status, and duration
