import fs from 'fs';
import path from 'path';
import { UploadService } from './upload.service';

/**
 * Shared-workspace layout for HalluciShield.
 *
 * Both the backend and the AI engine mount the same named volume at
 * `/workspace` (docker-compose). The layout is:
 *
 *   /workspace
 *   ├── archives/<repositoryId>.zip   - staged upload archive (backend-owned)
 *   └── runs/<scanId>/                - per-scan isolated extraction target
 *
 * Outside Docker the root defaults to `backend/uploads/extracted` so local
 * development keeps the historical on-disk behavior. Override with
 * `WORKSPACE_ROOT` (backend) / `HALLUCISHIELD_WORKSPACE_ROOT` (AI engine).
 *
 * The backend is the ONLY writer: it stages archives and materializes
 * per-scan workspaces by safely re-extracting the staged ZIP (zip-slip
 * protection preserved). The AI engine only reads run directories.
 */
export class WorkspaceService {
  /** Resolve (and cache) the shared workspace root. */
  private static cachedRoot: string | null = null;

  static getRoot(): string {
    if (WorkspaceService.cachedRoot) {
      return WorkspaceService.cachedRoot;
    }
    const fromEnv = (process.env.WORKSPACE_ROOT || '').trim();
    const root = path.resolve(fromEnv || path.resolve(__dirname, '../../uploads/extracted'));
    WorkspaceService.cachedRoot = root;
    return root;
  }

  /** Test seam: force a different root (e.g. a temp dir) for the process. */
  static setRootOverrideForTesting(root: string | null): void {
    WorkspaceService.cachedRoot = root ? path.resolve(root) : null;
  }

  static ensureRoot(create = true): string {
    const root = WorkspaceService.getRoot();
    if (create || !fs.existsSync(root)) {
      fs.mkdirSync(root, { recursive: true });
    }
    return root;
  }

  /** `/workspace/runs/<scanId>` — unique per scan, created on demand. */
  static runDir(scanId: string): string {
    const dir = path.join(WorkspaceService.ensureRoot(), 'runs', scanId);
    fs.mkdirSync(dir, { recursive: true });
    return dir;
  }

  /** `/workspace/runs/<scanId>.patched` — remediated copy of a scan workspace. */
  static patchedRunDir(scanId: string): string {
    const dir = path.join(WorkspaceService.ensureRoot(), 'runs', `${scanId}.patched`);
    fs.mkdirSync(dir, { recursive: true });
    return dir;
  }

  /** `/workspace/archives` staging area for uploaded ZIPs. */
  static archiveDir(): string {
    const dir = path.join(WorkspaceService.ensureRoot(), 'archives');
    fs.mkdirSync(dir, { recursive: true });
    return dir;
  }

  /** Absolute path where a repository's uploaded archive is staged. */
  static archivePath(repositoryId: string): string {
    return path.join(WorkspaceService.archiveDir(), `${repositoryId}.zip`);
  }

  /** True when `p` lives inside the shared workspace root and is backend-managed. */
  static isManagedPath(p: string): boolean {
    const root = path.join(WorkspaceService.getRoot(), path.sep);
    return path.resolve(p).startsWith(root);
  }

  /**
   * Materialize a scan workspace by safely extracting a staged archive into
   * `/workspace/runs/<scanId>`. Preserves all zip-slip / traversal defenses.
   */
  static materializeScanWorkspace(
    archivePath: string,
    scanId: string
  ): { workspacePath: string; managed: boolean } {
    if (!fs.existsSync(archivePath)) {
      throw new Error(`Staged archive not found on shared workspace: ${archivePath}`);
    }
    const dest = WorkspaceService.runDir(scanId);
    // Idempotent: a retried scan must not inherit stale files.
    UploadService.cleanupDirectory(dest);
    fs.mkdirSync(dest, { recursive: true });
    const result = UploadService.safeExtractZip(archivePath, dest);
    return { workspacePath: result.workspacePath, managed: true };
  }

  /**
   * Materialize a scan workspace by copying an existing directory (e.g. single-file workspace).
   */
  static materializeFromDirectory(
    sourceDir: string,
    scanId: string
  ): { workspacePath: string; managed: boolean } {
    if (!fs.existsSync(sourceDir)) {
      throw new Error(`Source workspace directory not found: ${sourceDir}`);
    }
    const dest = WorkspaceService.runDir(scanId);
    UploadService.cleanupDirectory(dest);
    fs.mkdirSync(dest, { recursive: true });
    fs.cpSync(sourceDir, dest, { recursive: true });
    return { workspacePath: dest, managed: true };
  }

  /** `/workspace/secured_outputs` staging area for secured output files. */
  static securedOutputDir(): string {
    const dir = path.join(WorkspaceService.ensureRoot(), 'secured_outputs');
    fs.mkdirSync(dir, { recursive: true });
    return dir;
  }

  /** Path for storing a scan's secured output file. */
  static securedFilePath(scanId: string, fileName: string): string {
    const dir = path.join(WorkspaceService.securedOutputDir(), scanId);
    fs.mkdirSync(dir, { recursive: true });
    return path.join(dir, fileName);
  }

  /** Best-effort removal of a backend-managed scan workspace. */
  static cleanupScanWorkspace(workspacePath: string): void {
    if (!WorkspaceService.isManagedPath(workspacePath)) {
      return;
    }
    UploadService.cleanupDirectory(workspacePath);
  }
}