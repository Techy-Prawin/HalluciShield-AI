# 07 - Shared Workspace

## Overview

The shared workspace architecture allows both the backend and AI engine to access the same filesystem through a Docker named volume mounted at `/workspace`.

## Directory Layout

```
/workspace
├── archives/
│   └── <repositoryId>.zip      # Staged upload archives (backend-owned)
└── runs/
    └── <scanId>/               # Per-scan isolated extraction target
        ├── src/
        │   ├── main.py
        │   └── ...
        └── requirements.txt
```

## Design Principles

1. **Backend is the sole writer**: Archives are staged and extracted only by the backend
2. **AI engine is read-only**: Analysis agents read from `/workspace/runs/<scanId>/`
3. **Per-scan isolation**: Each scan gets its own directory under `runs/`
4. **Automatic cleanup**: Managed workspaces are cleaned after scan completion/failure

## WorkspaceService (`backend/src/services/workspace.service.ts`)

### Key Methods

| Method | Description |
|--------|-------------|
| `getRoot()` | Returns workspace root from `WORKSPACE_ROOT` env (default: `backend/uploads/extracted`) |
| `runDir(scanId)` | Returns `/workspace/runs/<scanId>` (creates if needed) |
| `archivePath(repoId)` | Returns `/workspace/archives/<repoId>.zip` |
| `archiveDir()` | Returns `/workspace/archives/` (creates if needed) |
| `materializeScanWorkspace(archivePath, scanId)` | Extracts staged archive into `runs/<scanId>/` with zip-slip protection |
| `cleanupScanWorkspace(workspacePath)` | Removes managed workspace directory |
| `isManagedPath(p)` | Checks if path is inside workspace root |
| `setRootOverrideForTesting(root)` | Test seam to override root |

### Archive Staging (Upload Flow)

1. Upload route receives `.zip` file
2. `fs.copyFile()` stages archive to `WorkspaceService.archivePath(repoId)`
3. `UploadService.safeExtractZip()` extracts to `WorkspaceService.runDir(repoId)`
4. Metadata stored with `archive_path` reference

### Workspace Materialization (Scan Flow)

1. Scan route generates `scanId`
2. If no `body.workspacePath` provided (standard flow):
   - `WorkspaceService.materializeScanWorkspace(archivePath, scanId)`
   - Cleans destination, re-extracts from staged archive
3. If `body.workspacePath` provided (legacy flow): uses it directly
4. AI engine receives `workspace_path` pointing to `/workspace/runs/<scanId>/`

### Cleanup

After scan reaches terminal state (COMPLETED or FAILED):
- `WorkspaceService.cleanupScanWorkspace(workspacePath)` is called
- Only cleans paths inside workspace root (`isManagedPath()` check)
- Best-effort: errors logged, not thrown

## AI Engine Workspace Access

`ai-engine/app/security.py` enforces workspace restrictions:

```python
WORKSPACE_ROOT_ENV = "HALLUCISHIELD_WORKSPACE_ROOT"

def validate_workspace_path(workspace_path, allowed_base=None):
    # Rejects ".." traversal
    # When HALLUCISHIELD_WORKSPACE_ROOT is set, enforces path is inside root
    # Returns resolved absolute path
```

Each API endpoint calls `validate_workspace_path()` before file access:
- `POST /api/v1/hallucination/detect`
- `POST /api/v1/security/scan`
- `POST /api/v1/dependency/analyze`
- `GET /api/v1/risk/repositories/{id}/risk`

## Local Development

Outside Docker, `WORKSPACE_ROOT` defaults to `backend/uploads/extracted`, preserving historical on-disk behavior. The AI engine runs without `HALLUCISHIELD_WORKSPACE_ROOT` set, so it can access any path (backward-compatible).

## Zip-Slip Protection

All extraction goes through `UploadService.safeExtractZip()`:
- Validates each file path in the archive
- Rejects paths containing `..` or absolute paths
- Ensures extracted files stay within target directory
