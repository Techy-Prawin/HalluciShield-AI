# 12 - Upload Flow

## Overview

The upload flow handles repository ingestion: accepting a `.zip` archive, staging it on the shared workspace, extracting files, and storing metadata.

## Flow Diagram

```
Frontend                    Backend                     Shared Workspace
   │                           │                              │
   │  POST /api/repositories/  │                              │
   │  upload (multipart)       │                              │
   │──────────────────────────>│                              │
   │                           │  1. Generate repoId          │
   │                           │  2. Stage archive            │
   │                           │  ─────────────────────────>  │
   │                           │  /workspace/archives/        │
   │                           │  <repoId>.zip                │
   │                           │                              │
   │                           │  3. Extract files            │
   │                           │  ─────────────────────────>  │
   │                           │  /workspace/runs/<repoId>/   │
   │                           │  ├── src/                    │
   │                           │  └── ...                     │
   │                           │                              │
   │                           │  4. Store metadata in DB     │
   │                           │                              │
   │  201 Created              │                              │
   │  { repository: {...} }    │                              │
   │<──────────────────────────│                              │
```

## Step-by-Step

### 1. Frontend Validation

`frontend/app/components/UploadPortal.tsx`:
- Accepts only `.zip` files
- Maximum size: 50MB
- Uses `XMLHttpRequest` for upload progress tracking

### 2. Backend Processing

`backend/src/routes/repository.router.ts`:

```typescript
// Generate unique repository ID
const repoId = crypto.randomUUID();

// Stage archive to shared workspace
const archiveDest = WorkspaceService.archivePath(repoId);
await fs.copyFile(file.path, archiveDest);

// Extract with zip-slip protection
const extraction = UploadService.safeExtractZip(archiveDest, runDir);

// Store metadata
const metadata = {
  fileCount: extraction.fileCount,
  language: extraction.language,
  workspacePath: extraction.workspacePath,
  archive_path: archiveDest,
};
```

### 3. Archive Staging

Archive copied to: `/workspace/archives/<repoId>.zip`

This staged archive is preserved for:
- Scan-time workspace materialization
- Re-extraction if scan workspace is cleaned

### 4. File Extraction

Extracted to: `/workspace/runs/<repoId>/`

`UploadService.safeExtractZip()`:
- Validates each path in the ZIP
- Rejects `..` traversal attempts
- Ensures files stay within target directory
- Returns file count, detected language, and workspace path

### 5. Metadata Storage

Stored in `repositories` table:
- `name`: Original archive filename
- `url`: Workspace path
- `language`: Detected primary language
- `metadata.fileCount`: Number of source files
- `metadata.archive_path`: Path to staged archive

### 6. Response

```json
{
  "success": true,
  "repository": {
    "id": "uuid",
    "name": "my-repo.zip",
    "language": "python",
    "fileCount": 42,
    "status": "INGESTED",
    "workspacePath": "/workspace/runs/<repoId>",
    "createdAt": "2026-09-03T..."
  }
}
```

## Error Cases

| Error | HTTP Status | Description |
|-------|-------------|-------------|
| Invalid file type | 400 | Not a `.zip` file |
| File too large | 413 | Exceeds 50MB limit |
| Zip-slip detected | 400 | Malicious path in archive |
| Extraction failed | 500 | Corrupt or invalid ZIP |

## Test Coverage

`backend/tests/upload.test.ts`:
- Upload returns fileCount, language, workspacePath
- Extracted files exist on disk
- Metadata stored correctly
- Zip-slip protection works
- Invalid file types rejected
