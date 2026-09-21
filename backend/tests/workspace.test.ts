import request from 'supertest';
import path from 'path';
import fs from 'fs';
import AdmZip from 'adm-zip';
import { createApp } from '../src/app';
import { pool, checkDatabaseHealth } from '../src/config/db';
import { runMigrations } from '../src/db/migrate';
import { UploadService } from '../src/services/upload.service';
import { WorkspaceService } from '../src/services/workspace.service';
import { AiEngineClient } from '../src/services/aiEngine.client';
import { OrchestrationService } from '../src/services/orchestration.service';
import { setOrchestrationServiceForTesting } from '../src/routes/orchestration.router';

const ROOT = path.resolve(__dirname, 'temp_test_workspace');

function makeZip(zipPath: string, files: Record<string, string>): string {
  const zip = new AdmZip();
  for (const [filePath, content] of Object.entries(files)) {
    zip.addFile(filePath, Buffer.from(content, 'utf8'));
  }
  zip.writeZip(zipPath);
  return zipPath;
}

function okStages(): Record<string, any> {
  return {
    '/api/v1/hallucination/detect': { status: 200, ok: true, data: { findings: [] } },
    '/api/v1/security/scan': { status: 200, ok: true, data: { total_vulnerabilities: 0 } },
    '/api/v1/dependency/analyze': { status: 200, ok: true, data: { dependency_findings: [] } },
  };
}

async function pollScanUntilFinished(
  app: any,
  repositoryId: string,
  scanId: string,
  timeoutMs = 10000
): Promise<any> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const res = await request(app).get(`/api/repositories/${repositoryId}/scan/${scanId}/status`);
    if (res.body.status === 'COMPLETED' || res.body.status === 'FAILED') {
      return res.body;
    }
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error(`Scan ${scanId} did not finish within ${timeoutMs}ms`);
}

describe('Shared workspace architecture (backend materializes /workspace/runs/<scanId>)', () => {
  beforeAll(() => {
    WorkspaceService.setRootOverrideForTesting(ROOT);
    fs.mkdirSync(ROOT, { recursive: true });
  });

  afterEach(() => {
    UploadService.cleanupDirectory(ROOT);
  });

  afterAll(() => {
    UploadService.cleanupDirectory(ROOT);
    WorkspaceService.setRootOverrideForTesting(null);
  });

  test('staged archive is stored under the shared workspace root and re-extracted per scan', () => {
    const repoId = 'repo-101';
    const archive = WorkspaceService.archivePath(repoId);
    makeZip(archive, {
      'src/index.ts': 'export const x = 1;',
      'package.json': '{"name":"ws-repo","version":"1.0.0"}',
    });

    expect(WorkspaceService.isManagedPath(archive)).toBe(true);
    expect(archive).toBe(path.join(ROOT, 'archives', `${repoId}.zip`));

    const scanA = WorkspaceService.materializeScanWorkspace(archive, 'scan-A');
    const scanB = WorkspaceService.materializeScanWorkspace(archive, 'scan-B');

    expect(scanA.managed).toBe(true);
    expect(scanB.managed).toBe(true);
    expect(scanA.workspacePath).toBe(path.join(ROOT, 'runs', 'scan-A'));
    expect(scanB.workspacePath).toBe(path.join(ROOT, 'runs', 'scan-B'));
    expect(scanA.workspacePath).not.toBe(scanB.workspacePath);

    // Both scans read identical repo content from the shared volume.
    for (const ws of [scanA.workspacePath, scanB.workspacePath]) {
      expect(fs.existsSync(path.join(ws, 'src/index.ts'))).toBe(true);
      expect(fs.existsSync(path.join(ws, 'package.json'))).toBe(true);
    }

    // Cleanup is scoped to a single scan run directory.
    UploadService.cleanupDirectory(scanA.workspacePath);
    expect(fs.existsSync(scanA.workspacePath)).toBe(false);
    expect(fs.existsSync(scanB.workspacePath)).toBe(true);
  });

  test('scan workspaces are isolated from each other', () => {
    const archiveA = WorkspaceService.archivePath('repo-isolation-a');
    const archiveB = WorkspaceService.archivePath('repo-isolation-b');
    makeZip(archiveA, { 'a.txt': 'content-a' });
    makeZip(archiveB, { 'b.txt': 'content-b' });

    const wsA = WorkspaceService.materializeScanWorkspace(archiveA, 'scan-isolated-a');
    const wsB = WorkspaceService.materializeScanWorkspace(archiveB, 'scan-isolated-b');

    expect(fs.existsSync(path.join(wsA.workspacePath, 'a.txt'))).toBe(true);
    expect(fs.existsSync(path.join(wsA.workspacePath, 'b.txt'))).toBe(false);
    expect(fs.existsSync(path.join(wsB.workspacePath, 'b.txt'))).toBe(true);
    expect(fs.existsSync(path.join(wsB.workspacePath, 'a.txt'))).toBe(false);
  });

  test('zip-slip protection is preserved when materializing a scan workspace', () => {
    const badArchive = WorkspaceService.archivePath('repo-evil');
    const zip = new AdmZip();
    zip.addFile('ok.ts', Buffer.from('const ok = 1;'));
    zip.addFile('payload.txt', Buffer.from('evil'));
    const entry = zip.getEntries().find((e) => e.entryName === 'payload.txt');
    if (entry) {
      entry.entryName = '../escaped.txt';
    }
    zip.writeZip(badArchive);

    expect(() => WorkspaceService.materializeScanWorkspace(badArchive, 'scan-evil')).toThrow(
      /Malicious archive detected|Path traversal/i
    );
    const escapeTarget = path.resolve(ROOT, '../escaped.txt');
    expect(fs.existsSync(escapeTarget)).toBe(false);
  });
});

describe('HTTP flow: upload stages archive, scan materializes per-scan workspace for the AI engine', () => {
  const uploadDir = path.resolve(__dirname, 'temp_test_ws_upload');
  let isDbAvailable = false;

  beforeAll(async () => {
    WorkspaceService.setRootOverrideForTesting(uploadDir);
    fs.mkdirSync(uploadDir, { recursive: true });
    const health = await checkDatabaseHealth();
    isDbAvailable = health.connected;
    if (isDbAvailable) {
      await runMigrations();
    }
  });

  afterAll(async () => {
    UploadService.cleanupDirectory(uploadDir);
    WorkspaceService.setRootOverrideForTesting(null);
    if (isDbAvailable) {
      await pool.end();
    }
  });

  it('upload -> scan (no body path): per-scan workspace created, AI engine reads it, cleaned up after', async () => {
    if (!isDbAvailable) {
      return; // archive resolution requires the repository registry
    }

    // Hold the hallucination stage so the managed workspace is observable
    // while the scan is actually running against the fake AI engine.
    let releaseDetect!: (v: any) => void;
    const detectGate = new Promise<any>((r) => {
      releaseDetect = r;
    });
    const responses = okStages();
    const calls: any[] = [];
    const fake = {
      calls,
      handler: async (opts: any) => {
        if (opts.path === '/api/v1/hallucination/detect') {
          return detectGate;
        }
        return responses[opts.path];
      },
      async request<T = any>(opts: any): Promise<any> {
        this.calls.push(opts);
        return this.handler(opts);
      },
    };
    setOrchestrationServiceForTesting(new OrchestrationService(fake as unknown as AiEngineClient));
    const app = createApp();

    const zipPath = path.join(uploadDir, 'repo-zip.zip');
    makeZip(zipPath, { 'src/index.ts': 'export const y = 2;' });

    const up = await request(app)
      .post('/api/repositories/upload')
      .attach('file', zipPath)
      .field('name', 'shared-ws-repo');
    expect(up.status).toBe(201);
    const repoId = up.body.repository.id;
    // The staged archive lives on the shared volume (metadata.archive_path).
    const { RepositoryModel } = await import('../src/models');
    const repoRow = await RepositoryModel.findById(repoId);
    const stagedArchive = repoRow?.metadata?.archive_path;
    expect(typeof stagedArchive).toBe('string');
    expect(fs.existsSync(stagedArchive as string)).toBe(true);

    const start = await request(app).post(`/api/repositories/${repoId}/scan`).send({});
    expect(start.status).toBe(202);
    expect(start.body.managedWorkspace).toBe(true);
    const expectedRun = path.join(uploadDir, 'runs', start.body.scanId);
    expect(start.body.workspacePath).toBe(expectedRun);

    // The per-scan workspace was materialized before the scan became RUNNING.
    await new Promise((r) => setTimeout(r, 20));
    expect(fs.existsSync(expectedRun)).toBe(true);
    expect(fs.existsSync(path.join(expectedRun, 'src/index.ts'))).toBe(true);

    // The AI engine received the per-scan shared workspace path.
    const scanCallsDeadline = Date.now() + 5000;
    let scanCalls: any[] = [];
    while (Date.now() < scanCallsDeadline && scanCalls.length === 0) {
      await new Promise((r) => setTimeout(r, 50));
      scanCalls = calls.filter((c: any) => c.body && c.body.workspace_path);
    }
    expect(scanCalls.length).toBeGreaterThan(0);
    for (const c of scanCalls) {
      expect(c.body.workspace_path).toBe(expectedRun);
    }

    // Release the gate, let the scan settle, confirm the managed workspace is removed.
    releaseDetect({ status: 200, ok: true, data: { findings: [] } });
    const finalStatus = await pollScanUntilFinished(app, repoId, start.body.scanId);
    expect(finalStatus.status).toBe('COMPLETED');

    const cleanupDeadline = Date.now() + 1000;
    while (fs.existsSync(expectedRun) && Date.now() < cleanupDeadline) {
      await new Promise((r) => setTimeout(r, 10));
    }
    expect(fs.existsSync(expectedRun)).toBe(false);
  });

  it('scan returns 400 when the staged archive cannot be materialized', async () => {
    if (!isDbAvailable) {
      return;
    }
    const res = okStages();
    const fake = {
      handler: async (opts: any) => res[opts.path],
      async request<T = any>(opts: any): Promise<any> {
        return this.handler(opts);
      },
    };
    setOrchestrationServiceForTesting(new OrchestrationService(fake as unknown as AiEngineClient));
    const app = createApp();

    const { RepositoryModel } = await import('../src/models');
    const corruptArchive = path.join(uploadDir, 'corrupt-stage.zip');
    fs.writeFileSync(corruptArchive, 'NOT_A_REAL_ZIP_HEADER');
    const created = await RepositoryModel.create({
      name: 'corrupt-archive',
      url: 'file:///nope',
      default_branch: 'main',
      language: 'typescript',
      is_active: true,
      metadata: {
        repository_id: 'repo-corrupt',
        workspace_path: '',
        archive_path: corruptArchive,
        status: 'INGESTED',
      },
    });

    try {
      const scan = await request(app).post(`/api/repositories/${created.id}/scan`).send({});
      expect(scan.status).toBe(400);
      expect(scan.body.success).toBe(false);
      expect(scan.body.error).toMatch(/Failed to materialize scan workspace/i);
    } finally {
      await RepositoryModel.delete(created.id);
      UploadService.cleanupFile(corruptArchive);
    }
  });
});