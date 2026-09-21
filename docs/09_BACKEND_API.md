# 09 - Backend API

## Overview

Express.js API gateway running on port 4000. Orchestrates uploads, scans, and AI engine communication.

## Entry Point

`backend/src/app.ts` → `backend/src/index.ts`

## Middleware Stack

1. **CORS** - Configurable origins
2. **Request ID** (`requestIdMiddleware`) - UUID per request, logged on finish
3. **JSON body parser** - 10mb limit
4. **Static uploads** - Serves `/uploads` directory

## Routes

### Health Check

```
GET /api/v1/health
```

Returns service status, database connectivity, and AI engine URL.

### Repository Management

```
POST /api/repositories/upload    # Upload .zip archive
GET  /api/repositories/:id      # Get repository details
```

**Upload flow**:
1. Accepts `multipart/form-data` with `.zip` file
2. Stages archive to `WorkspaceService.archivePath(repoId)`
3. Extracts into `WorkspaceService.runDir(repoId)` with zip-slip protection
4. Stores metadata (fileCount, language, workspacePath, archive_path)
5. Returns `201` with repository data

### Orchestration

```
POST /api/orchestration/scan           # Start a scan
GET  /api/orchestration/status/:id     # Get scan status
GET  /api/orchestration/results/:id    # Get scan results
POST /api/orchestration/cancel/:id     # Cancel a scan
GET  /api/orchestration/history        # List past scans
GET  /api/orchestration/metrics        # Aggregated metrics
POST /api/orchestration/patch/:id/approve  # Approve a patch
POST /api/orchestration/patch/:id/reject   # Reject a patch
GET  /api/orchestration/feedback       # Feedback history
GET  /api/orchestration/dashboard      # Dashboard summary
```

**Scan flow**:
1. Generate `scanId` via `crypto.randomUUID()`
2. Resolve workspace (body path → DB archive_path → materialize → fallback)
3. Create per-scan directory via `WorkspaceService.materializeScanWorkspace()`
4. Call `startScan()` in orchestration service
5. Returns `202 Accepted` with scanId

## Orchestration Service

`backend/src/services/orchestration.service.ts`

### ScanRecord (In-Memory Registry)

```typescript
interface ScanRecord {
  scanId: string;
  repositoryId: string;
  workspacePath: string;
  status: 'PENDING' | 'SCANNING' | 'COMPLETED' | 'FAILED';
  managedWorkspace: boolean;
  // ... timestamps, results, error
}
```

### startScan()

1. Creates in-memory `ScanRecord`
2. Sets status to `SCANNING`
3. Calls AI engine endpoints sequentially:
   - `POST /api/v1/hallucination/detect`
   - `POST /api/v1/security/scan`
   - `POST /api/v1/dependency/analyze`
4. Aggregates results
5. Sets status to `COMPLETED` or `FAILED`
6. Auto-cleans managed workspace after terminal state

### X-Request-ID Propagation

Backend propagates its request ID to AI engine calls via `X-Request-ID` header for distributed tracing.

## Error Handling

- AI engine error bodies passed through un-mangled
- 4xx from AI engine returned as-is to client
- 5xx from AI engine returned with original error detail
- All errors logged with request ID

## Database

`backend/src/config/db.ts` - PostgreSQL connection pool (max 10, 30s idle timeout).

Schema: `backend/src/db/schema.sql`

## File Structure

```
backend/src/
├── app.ts                    # Express app setup
├── index.ts                  # Server entry point
├── config/
│   ├── env.ts                # Environment configuration
│   └── db.ts                 # PostgreSQL pool
├── middleware/
│   └── requestId.ts          # Request ID assignment
├── routes/
│   ├── health.router.ts      # Health check
│   ├── repository.router.ts  # Upload & repository CRUD
│   └── orchestration.router.ts  # Scan lifecycle
├── services/
│   ├── orchestration.service.ts  # Scan orchestration
│   ├── upload.service.ts     # File upload & extraction
│   ├── workspace.service.ts  # Shared workspace management
│   └── aiEngine.client.ts    # AI engine HTTP client
├── models/
│   ├── types.ts              # TypeScript interfaces
│   └── repository.model.ts   # Repository DB queries
└── db/
    ├── schema.sql            # Database schema
    └── migrate.ts            # Migration runner
```
