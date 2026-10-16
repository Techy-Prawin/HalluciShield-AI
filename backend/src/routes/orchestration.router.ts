import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { Request, Response, NextFunction, Router } from 'express';
import { RepositoryModel } from '../models';
import { checkDatabaseHealth } from '../config/db';
import { AiEngineClient, AiEngineConnectionError } from '../services/aiEngine.client';
import { OrchestrationService, ScanRecord } from '../services/orchestration.service';
import { WorkspaceService } from '../services/workspace.service';
import { config } from '../config/env';

const router = Router();

let orchestrationService = new OrchestrationService(new AiEngineClient());

/** Test seam: allows injecting a fake AI engine gateway. */
export function setOrchestrationServiceForTesting(service: OrchestrationService): void {
  orchestrationService = service;
}

function getService(): OrchestrationService {
  return orchestrationService;
}

type Handler = (req: Request, res: Response) => Promise<void> | void;

function asyncHandler(fn: Handler) {
  return (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(fn(req, res)).catch(next);
  };
}

function fail(
  res: Response,
  status: number,
  error: string,
  extra: Record<string, unknown> = {}
): void {
  res.status(status).json({ success: false, error, requestId: res.locals.requestId, ...extra });
}

function emitAiEngineFailure(err: unknown, res: Response): void {
  if (err instanceof AiEngineConnectionError) {
    fail(res, err.status, err.message, { code: err.code });
    return;
  }
  console.error(
    `[orchestration] requestId=${res.locals.requestId ?? 'unknown'} AI engine proxy failed:`,
    err instanceof Error ? err.message : err
  );
  fail(res, 502, 'AI engine proxy failed unexpectedly.', { code: 'AI_ENGINE_PROXY_ERROR' });
}

interface ResolvedWorkspace {
  workspacePath: string;
  archivePath?: string;
}

async function resolveRepositoryWorkspace(repositoryId: string): Promise<ResolvedWorkspace | null> {
  try {
    const dbHealth = await checkDatabaseHealth();
    if (!dbHealth.connected) return null;
    const repo = await RepositoryModel.findById(repositoryId);
    if (!repo) return null;
    const ws = repo.metadata?.workspace_path;
    const ar = repo.metadata?.archive_path;
    return {
      workspacePath: typeof ws === 'string' && ws.trim() ? ws.trim() : '',
      archivePath: typeof ar === 'string' && ar.trim() ? ar.trim() : undefined,
    };
  } catch {
    return null;
  }
}

async function resolveSourceContext(repositoryId: string, scanId: string, filePath: string, lineNumber: number): Promise<string | null> {
  const scan = await getService().getScanAsync(scanId);
  const repository = await RepositoryModel.findById(repositoryId);
  const archivePath = repository?.metadata?.archive_path;
  if (!scan || typeof archivePath !== 'string' || !fs.existsSync(archivePath)) return null;

  const temporaryScanId = `context-${scanId}-${crypto.randomUUID()}`;
  let workspacePath: string | null = null;
  try {
    workspacePath = WorkspaceService.materializeScanWorkspace(archivePath, temporaryScanId).workspacePath;
    const resolvedRoot = path.resolve(workspacePath);
    const resolvedFile = path.resolve(resolvedRoot, filePath);
    if (!resolvedFile.startsWith(`${resolvedRoot}${path.sep}`) || !fs.existsSync(resolvedFile)) return null;
    const lines = fs.readFileSync(resolvedFile, 'utf8').split(/\r?\n/);
    const start = Math.max(0, Math.max(1, lineNumber) - 4);
    const end = Math.min(lines.length, Math.max(1, lineNumber) + 3);
    return lines.slice(start, end).join('\n');
  } finally {
    if (workspacePath) WorkspaceService.cleanupScanWorkspace(workspacePath);
  }
}

const AI_ENGINE_TIMEOUTS = {
  scan: 120_000,
  patches: 120_000,
  validation: 120_000,
  rank: 60_000,
  approval: 15_000,
  read: 10_000,
};

function isArtifactAuthorized(scan: Awaited<ReturnType<OrchestrationService['getScanAsync']>>): boolean {
  return Boolean(
    scan &&
    scan.status === 'COMPLETED' &&
    // Allow AUTHORIZED or UNVERIFIED_DOWNLOAD (with user acknowledgement)
    (scan.artifactAuthorization === 'AUTHORIZED' ||
     scan.artifactAuthorization === 'UNVERIFIED_DOWNLOAD') &&
    scan.stages.security.state === 'COMPLETED' &&
    scan.stages.security.details?.scannerStatus === 'COMPLETED' &&
    scan.stages.securedFile?.state === 'COMPLETED'
  );
}

// ---------------------------------------------------------------------------
// 1. POST /api/repositories/:repositoryId/scan — start a scan
// ---------------------------------------------------------------------------
router.post(
  '/repositories/:repositoryId/scan',
  asyncHandler(async (req: Request, res: Response) => {
    const { repositoryId } = req.params;
    const bodyWorkspacePath =
      typeof req.body?.workspacePath === 'string' && req.body.workspacePath.trim()
        ? req.body.workspacePath.trim()
        : null;

    // The scan workspace is pre-materialized so the AI engine can read it the
    // moment the first stage request is sent.
    const scanId = crypto.randomUUID();
    let workspacePath: string | null = null;
    let managedWorkspace = false;

    if (bodyWorkspacePath) {
      if (config.env === 'production' && !WorkspaceService.isManagedPath(bodyWorkspacePath)) {
        fail(res, 403, 'workspacePath must be inside the managed workspace root.');
        return;
      }
      if (config.env === 'production' && !fs.existsSync(bodyWorkspacePath)) {
        fail(res, 404, 'The requested workspace path does not exist.');
        return;
      }
      workspacePath = bodyWorkspacePath;
    } else {
      const workspace = await resolveRepositoryWorkspace(repositoryId);
      if (workspace) {
        if (workspace.archivePath && fs.existsSync(workspace.archivePath)) {
          // Docker shared-volume flow: create /workspace/runs/<scanId> by
          // safely re-extracting the staged archive.
          try {
            const materialized = WorkspaceService.materializeScanWorkspace(
              workspace.archivePath,
              scanId
            );
            workspacePath = materialized.workspacePath;
            managedWorkspace = materialized.managed;
          } catch (err) {
            fail(res, 400, `Failed to materialize scan workspace. ${err instanceof Error ? err.message : String(err)}`);
            return;
          }
        } else if (workspace.workspacePath && fs.existsSync(workspace.workspacePath)) {
          try {
            const materialized = WorkspaceService.materializeFromDirectory(
              workspace.workspacePath,
              scanId
            );
            workspacePath = materialized.workspacePath;
            managedWorkspace = materialized.managed;
          } catch {
            workspacePath = workspace.workspacePath;
            managedWorkspace = false;
          }
        }
      }
    }

    if (!workspacePath) {
      fail(
        res,
        404,
        'Repository not found or workspace path unavailable. Upload the repository again or provide workspacePath in the request body.'
      );
      return;
    }

    const scan = getService().startScan(repositoryId, workspacePath, scanId, { managedWorkspace });
    res.status(202).json({
      success: true,
      message: 'Scan queued against AI engine.',
      scanId: scan.id,
      repositoryId,
      status: scan.status,
      workspacePath,
      managedWorkspace,
      requestId: res.locals.requestId,
    });
  })
);

// ---------------------------------------------------------------------------
// 2. GET /api/repositories/:repositoryId/scan/:scanId/status
// ---------------------------------------------------------------------------
router.get(
  '/repositories/:repositoryId/scan/:scanId/status',
  asyncHandler(async (req: Request, res: Response) => {
    const scan = await getService().getScanAsync(req.params.scanId);
    if (!scan || scan.repositoryId !== req.params.repositoryId) {
      fail(res, 404, 'Scan not found.');
      return;
    }
    const hasOutputFile = Boolean(isArtifactAuthorized(scan) && scan.outputFile && fs.existsSync(scan.outputFile));
    res.status(200).json({
      success: true,
      scanId: scan.id,
      repositoryId: scan.repositoryId,
      status: scan.status,
      currentStage: scan.currentStage,
      stages: scan.stages,
      error: scan.error ?? null,
      createdAt: scan.createdAt,
      updatedAt: scan.updatedAt,
      completedAt: scan.completedAt ?? null,
      // Authoritative findings & stage artifacts for the whole pipeline.
      hallucinationFindings: scan.results?.hallucination ?? null,
      securityFindings: scan.results?.security ?? null,
      dependencyFindings: scan.results?.dependency ?? null,
      riskAssessment: scan.results?.risk ?? null,
      riskScore: scan.riskScore,
      riskLevel: scan.riskLevel,
      confidence: scan.confidence,
      patches: scan.patches,
      validationResults: scan.results?.validation ?? null,
      remediation: scan.remediation ?? null,
      remediationStatus: scan.remediationStatus,
      artifactAuthorization: scan.artifactAuthorization,
      securityVerdict: scan.securityVerdict,
      downloadEligibility: scan.downloadEligibility ?? null,
      downloadAcknowledgement: scan.downloadAcknowledgement ?? null,
      hasOutputFile,
      downloadUrl: hasOutputFile ? `/api/repositories/${scan.repositoryId}/scan/${scan.id}/download` : null,
      outputFile: scan.outputFile ? path.basename(scan.outputFile) : null,
      securedFileName: scan.outputFile && hasOutputFile ? path.basename(scan.outputFile) : null,
      originalFileName: scan.originalFileName,
      uploadType: scan.uploadType,
      requestId: res.locals.requestId,
    });
  })
);

// ---------------------------------------------------------------------------
// 3. GET /api/repositories/:repositoryId/scan/:scanId/findings
// ---------------------------------------------------------------------------
router.get(
  '/repositories/:repositoryId/scan/:scanId/findings',
  asyncHandler(async (req: Request, res: Response) => {
    const scan = await getService().getScanAsync(req.params.scanId);
    if (!scan || scan.repositoryId !== req.params.repositoryId) {
      fail(res, 404, 'Scan not found.');
      return;
    }

    if (scan.status === 'QUEUED' || scan.status === 'RUNNING') {
      res.status(202).json({
        success: true,
        message: 'Scan still in progress. Poll status before fetching findings.',
        scanId: scan.id,
        status: scan.status,
        requestId: res.locals.requestId,
      });
      return;
    }

    const successfulStages = Object.values(scan.stages).filter((s) => s.state === 'COMPLETED').length;
    const hasOutputFile = Boolean(isArtifactAuthorized(scan) && scan.outputFile && fs.existsSync(scan.outputFile));
    res.status(scan.status === 'FAILED' && successfulStages === 0 ? 502 : 200).json({
      success: scan.status === 'COMPLETED',
      scanId: scan.id,
      repositoryId: scan.repositoryId,
      status: scan.status,
      currentStage: scan.currentStage,
      error: scan.error ?? null,
      stages: scan.stages,
      hallucinationFindings: scan.results?.hallucination ?? null,
      securityFindings: scan.results?.security ?? null,
      dependencyFindings: scan.results?.dependency ?? null,
      riskAssessment: scan.results?.risk ?? null,
      riskScore: scan.riskScore,
      riskLevel: scan.riskLevel,
      confidence: scan.confidence,
      remediation: scan.remediation ?? null,
      remediationStatus: scan.remediationStatus,
      artifactAuthorization: scan.artifactAuthorization,
      securityVerdict: scan.securityVerdict,
      downloadEligibility: scan.downloadEligibility ?? null,
      patches: scan.patches,
      validationResults: scan.results?.validation ?? null,
      hasOutputFile,
      downloadUrl: hasOutputFile ? `/api/repositories/${scan.repositoryId}/scan/${scan.id}/download` : null,
      outputFile: scan.outputFile ? path.basename(scan.outputFile) : null,
      securedFileName: scan.outputFile && hasOutputFile ? path.basename(scan.outputFile) : null,
      originalFileName: scan.originalFileName,
      uploadType: scan.uploadType,
      requestId: res.locals.requestId,
    });
  })
);

// ---------------------------------------------------------------------------
// 3b. GET /api/repositories/:repositoryId/scan/:scanId/download — download secured file
// ---------------------------------------------------------------------------
router.get(
  '/repositories/:repositoryId/scan/:scanId/download',
  asyncHandler(async (req: Request, res: Response) => {
    const scan = await getService().getScanAsync(req.params.scanId);
    if (!scan || scan.repositoryId !== req.params.repositoryId) {
      fail(res, 404, 'Scan not found.');
      return;
    }
    if (!scan.outputFile || !fs.existsSync(scan.outputFile)) {
      // Provide more specific feedback based on authorization level
      if (scan.artifactAuthorization === 'UNVERIFIED_DOWNLOAD') {
        fail(res, 403, 'Download eligible with unverified status. Acknowledge the risk warning to proceed.');
      } else {
        fail(res, 404, 'Secured output file is not available yet for this scan.');
      }
      return;
    }

    // Blocked or pending artifacts are never downloadable, even if a file
    // happens to exist on disk (e.g. a stale artifact placed by a test).
    if (scan.artifactAuthorization === 'BLOCKED' || scan.artifactAuthorization === 'PENDING') {
      fail(res, 404, 'Secured output is not authorized for download.');
      return;
    }

    // Unverified downloads require an explicit, auditable acknowledgement.
    if (
      scan.artifactAuthorization === 'UNVERIFIED_DOWNLOAD' &&
      scan.downloadEligibility?.acknowledgementRequired === true &&
      !isUnverifiedDownloadAcknowledged(req, scan)
    ) {
      fail(res, 403, 'Download eligible with unverified status. Acknowledge the risk warning to proceed.', {
        acknowledgementRequired: true,
      });
      return;
    }

    // Integrity check: the artifact on disk must match the scanned candidate's hash.
    const actualHash = crypto.createHash('sha256').update(fs.readFileSync(scan.outputFile)).digest('hex');
    if (scan.outputFileHash && actualHash !== scan.outputFileHash) {
      fail(res, 409, 'Artifact integrity check failed: secured output does not match the scanned candidate. Download blocked.', {
        code: 'ARTIFACT_TAMPERED',
      });
      return;
    }

    const filename = path.basename(scan.outputFile);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('X-Content-SHA256', actualHash);
    const stream = fs.createReadStream(scan.outputFile);
    stream.pipe(res);
  })
);

/** True when the request carries an explicit acknowledgement for an
 * unverified download (query param, header, or a previously recorded
 * acknowledgement on the scan record). */
function isUnverifiedDownloadAcknowledged(req: Request, scan: ScanRecord): boolean {
  if (scan.downloadAcknowledgement) return true;
  if (req.query.acknowledge === 'true') return true;
  return req.headers['x-acknowledge-unverified-risk'] === 'true';
}

// ---------------------------------------------------------------------------
// 3c. POST /api/repositories/:repositoryId/scan/:scanId/acknowledge-download — record explicit acknowledgement
// ---------------------------------------------------------------------------
router.post(
  '/repositories/:repositoryId/scan/:scanId/acknowledge-download',
  asyncHandler(async (req: Request, res: Response) => {
    const scan = await getService().getScanAsync(req.params.scanId);
    if (!scan || scan.repositoryId !== req.params.repositoryId) {
      fail(res, 404, 'Scan not found.');
      return;
    }
    if (scan.artifactAuthorization !== 'UNVERIFIED_DOWNLOAD') {
      fail(res, 400, 'Acknowledgement is only applicable to unverified downloads.');
      return;
    }
    if (!scan.downloadEligibility?.acknowledgementRequired) {
      fail(res, 400, 'Acknowledgement is not required for this scan.');
      return;
    }
    if (!scan.outputFile || !fs.existsSync(scan.outputFile)) {
      fail(res, 404, 'Secured output file is not available for this scan.');
      return;
    }

    const body = req.body ?? {};
    if (body.acknowledged !== true) {
      fail(res, 400, 'Explicit acknowledgement is required.');
      return;
    }

    const acknowledged = getService().acknowledgeDownload(scan.id, {
      acknowledgedAt: new Date().toISOString(),
      acknowledgedBy: typeof body.userId === 'string' && body.userId.trim() ? body.userId.trim() : undefined,
      userId: typeof body.userId === 'string' && body.userId.trim() ? body.userId.trim() : undefined,
      ip: req.ip,
      level: 'UNVERIFIED_DOWNLOAD',
    });
    if (!acknowledged) {
      fail(res, 404, 'Scan not found.');
      return;
    }

    res.status(200).json({
      success: true,
      scanId: scan.id,
      acknowledged: true,
      level: 'UNVERIFIED_DOWNLOAD',
      acknowledgedAt: scan.downloadAcknowledgement?.acknowledgedAt,
      message: 'Unverified download acknowledgement recorded. Proceed to the download endpoint.',
      requestId: res.locals.requestId,
    });
  })
);

// ---------------------------------------------------------------------------
// 4. POST /api/repositories/:repositoryId/scan/:scanId/patches — generate patches
// ---------------------------------------------------------------------------
router.post(
  '/repositories/:repositoryId/scan/:scanId/patches',
  asyncHandler(async (req: Request, res: Response) => {
    const { repositoryId, scanId } = req.params;
    const scan = await getService().getScanAsync(scanId);
    if (!scan || scan.repositoryId !== repositoryId) {
      fail(res, 404, 'Scan not found.');
      return;
    }

    const body = req.body ?? {};
    if (typeof body.vulnerable_code !== 'string' || !body.vulnerable_code.trim()) {
      fail(res, 400, 'vulnerable_code is required and must not be empty.');
      return;
    }

    const vulnerabilityId =
      typeof body.vulnerability_id === 'string' && body.vulnerability_id.trim()
        ? body.vulnerability_id.trim()
        : `vuln-${crypto.randomUUID()}`;

    if (typeof body.file === 'string' && (!body.surrounding_code || body.surrounding_code === body.vulnerable_code)) {
      const context = await resolveSourceContext(repositoryId, scanId, body.file, Number(body.line) || 1);
      if (context) body.surrounding_code = context;
    }

    try {
      const r = await getService().proxy({
        method: 'POST',
        path: `/api/v1/vulnerabilities/${encodeURIComponent(vulnerabilityId)}/generate-patches`,
        body: { ...body, vulnerability_id: vulnerabilityId },
        timeoutMs: AI_ENGINE_TIMEOUTS.patches,
        requestId: res.locals.requestId,
      });

      if (!r.ok) {
        res.status(r.status).json(r.data);
        return;
      }
      getService().setPatches(scanId, vulnerabilityId, r.data);
      res.status(200).json({
        success: true,
        scanId,
        vulnerabilityId,
        message: 'Patch candidates generated.',
        ...r.data,
        requestId: res.locals.requestId,
      });
    } catch (err) {
      emitAiEngineFailure(err, res);
    }
  })
);

// ---------------------------------------------------------------------------
// 4b. GET /api/repositories/:repositoryId/scan/:scanId/patches — cached patches
// ---------------------------------------------------------------------------
router.get(
  '/repositories/:repositoryId/scan/:scanId/patches',
  asyncHandler(async (req: Request, res: Response) => {
    const { repositoryId, scanId } = req.params;
    const scan = await getService().getScanAsync(scanId);
    if (!scan || scan.repositoryId !== repositoryId) {
      fail(res, 404, 'Scan not found.');
      return;
    }
    res.status(200).json({
      success: true,
      scanId,
      patches: scan.patches,
      requestId: res.locals.requestId,
    });
  })
);

// ---------------------------------------------------------------------------
// 5. POST /api/repositories/:repositoryId/scan/:scanId/validate
// ---------------------------------------------------------------------------
router.post(
  '/repositories/:repositoryId/scan/:scanId/validate',
  asyncHandler(async (req: Request, res: Response) => {
    const { repositoryId, scanId } = req.params;
    const scan = await getService().getScanAsync(scanId);
    if (!scan || scan.repositoryId !== repositoryId) {
      fail(res, 404, 'Scan not found.');
      return;
    }

    const body = req.body ?? {};
    if (typeof body.vulnerability_id !== 'string' || !body.vulnerability_id.trim()) {
      fail(res, 400, 'vulnerability_id is required.');
      return;
    }
    if (!Array.isArray(body.candidates) || body.candidates.length === 0) {
      fail(res, 400, 'candidates must be a non-empty array.');
      return;
    }

    if (typeof body.file_path === 'string' && typeof body.original_code === 'string') {
      const context = await resolveSourceContext(repositoryId, scanId, body.file_path, 1);
      if (context && body.original_code.split(/\r?\n/).length <= 2) body.original_code = context;
    }

    try {
      const r = await getService().proxy({
        method: 'POST',
        path: `/api/v1/vulnerabilities/${encodeURIComponent(body.vulnerability_id)}/validate-candidates`,
        body,
        timeoutMs: AI_ENGINE_TIMEOUTS.validation,
        requestId: res.locals.requestId,
      });
      res.status(r.status).json(r.data);
    } catch (err) {
      emitAiEngineFailure(err, res);
    }
  })
);

// ---------------------------------------------------------------------------
// 5b. POST /api/repositories/:repositoryId/scan/:scanId/sandbox-validate
// ---------------------------------------------------------------------------
router.post(
  '/repositories/:repositoryId/scan/:scanId/sandbox-validate',
  asyncHandler(async (req: Request, res: Response) => {
    const { repositoryId, scanId } = req.params;
    const scan = await getService().getScanAsync(scanId);
    if (!scan || scan.repositoryId !== repositoryId) {
      fail(res, 404, 'Scan not found.');
      return;
    }

    const body = req.body ?? {};
    if (!body.patch || typeof body.file_path !== 'string' || typeof body.original_code !== 'string') {
      fail(res, 400, 'patch, file_path, and original_code are required.');
      return;
    }

    try {
      const r = await getService().proxy({
        method: 'POST',
        path: `/api/v1/vulnerabilities/${encodeURIComponent(body.vulnerability_id || 'sandbox-validation')}/validate-patch`,
        body,
        timeoutMs: AI_ENGINE_TIMEOUTS.validation,
        requestId: res.locals.requestId,
      });
      res.status(r.status).json(r.data);
    } catch (err) {
      emitAiEngineFailure(err, res);
    }
  })
);

// ---------------------------------------------------------------------------
// 6. POST /api/repositories/:repositoryId/scan/:scanId/rank — confidence ranking
// ---------------------------------------------------------------------------
router.post(
  '/repositories/:repositoryId/scan/:scanId/rank',
  asyncHandler(async (req: Request, res: Response) => {
    const { repositoryId, scanId } = req.params;
    const scan = await getService().getScanAsync(scanId);
    if (!scan || scan.repositoryId !== repositoryId) {
      fail(res, 404, 'Scan not found.');
      return;
    }

    const body = req.body ?? {};
    if (typeof body.vulnerability_id !== 'string' || !body.vulnerability_id.trim()) {
      fail(res, 400, 'vulnerability_id is required.');
      return;
    }
    if (!Array.isArray(body.validation_results) || body.validation_results.length === 0) {
      fail(res, 400, 'validation_results must be a non-empty array.');
      return;
    }

    try {
      const r = await getService().proxy({
        method: 'POST',
        path: `/api/v1/vulnerabilities/${encodeURIComponent(body.vulnerability_id)}/rank-patches`,
        body,
        timeoutMs: AI_ENGINE_TIMEOUTS.rank,
        requestId: res.locals.requestId,
      });
      res.status(r.status).json(r.data);
    } catch (err) {
      emitAiEngineFailure(err, res);
    }
  })
);

// ---------------------------------------------------------------------------
// 6b. POST /api/repositories/:repositoryId/scan/:scanId/recommendation
// ---------------------------------------------------------------------------
router.post(
  '/repositories/:repositoryId/scan/:scanId/recommendation',
  asyncHandler(async (req: Request, res: Response) => {
    const { repositoryId, scanId } = req.params;
    const scan = await getService().getScanAsync(scanId);
    if (!scan || scan.repositoryId !== repositoryId) {
      fail(res, 404, 'Scan not found.');
      return;
    }

    const body = req.body ?? {};
    if (typeof body.vulnerability_id !== 'string' || !body.vulnerability_id.trim()) {
      fail(res, 400, 'vulnerability_id is required.');
      return;
    }
    if (!Array.isArray(body.validation_results) || body.validation_results.length === 0) {
      fail(res, 400, 'validation_results must be a non-empty array.');
      return;
    }

    const safetyThreshold =
      typeof body.safety_threshold === 'number' ? body.safety_threshold : 50.0;

    try {
      const r = await getService().proxy({
        method: 'POST',
        path: `/api/v1/vulnerabilities/${encodeURIComponent(body.vulnerability_id)}/recommendation`,
        query: { safety_threshold: safetyThreshold },
        body,
        timeoutMs: AI_ENGINE_TIMEOUTS.rank,
        requestId: res.locals.requestId,
      });
      res.status(r.status).json(r.data);
    } catch (err) {
      emitAiEngineFailure(err, res);
    }
  })
);

// ---------------------------------------------------------------------------
// 7 & 8. POST .../patches/:patchId/approve | reject
// ---------------------------------------------------------------------------
router.post(
  '/repositories/:repositoryId/scan/:scanId/patches/:patchId/approve',
  asyncHandler(async (req: Request, res: Response) => {
    const { repositoryId, scanId, patchId } = req.params;
    const scan = await getService().getScanAsync(scanId);
    if (!scan || scan.repositoryId !== repositoryId) {
      fail(res, 404, 'Scan not found.');
      return;
    }

    const body = req.body ?? {};
    if (typeof body.developer_id !== 'string' || !body.developer_id.trim()) {
      fail(res, 400, 'developer_id is required.');
      return;
    }
    if (typeof body.vulnerability_id !== 'string' || !body.vulnerability_id.trim()) {
      fail(res, 400, 'vulnerability_id is required.');
      return;
    }

    try {
      const r = await getService().proxy({
        method: 'POST',
        path: `/api/v1/vulnerabilities/${encodeURIComponent(body.vulnerability_id)}/patches/${encodeURIComponent(patchId)}/approve`,
        body: { ...body, patch_id: patchId, vulnerability_id: body.vulnerability_id },
        timeoutMs: AI_ENGINE_TIMEOUTS.approval,
        requestId: res.locals.requestId,
      });
      res.status(r.status).json(r.data);
    } catch (err) {
      emitAiEngineFailure(err, res);
    }
  })
);

router.post(
  '/repositories/:repositoryId/scan/:scanId/patches/:patchId/reject',
  asyncHandler(async (req: Request, res: Response) => {
    const { repositoryId, scanId, patchId } = req.params;
    const scan = await getService().getScanAsync(scanId);
    if (!scan || scan.repositoryId !== repositoryId) {
      fail(res, 404, 'Scan not found.');
      return;
    }

    const body = req.body ?? {};
    if (typeof body.developer_id !== 'string' || !body.developer_id.trim()) {
      fail(res, 400, 'developer_id is required.');
      return;
    }
    if (typeof body.vulnerability_id !== 'string' || !body.vulnerability_id.trim()) {
      fail(res, 400, 'vulnerability_id is required.');
      return;
    }

    try {
      const r = await getService().proxy({
        method: 'POST',
        path: `/api/v1/vulnerabilities/${encodeURIComponent(body.vulnerability_id)}/patches/${encodeURIComponent(patchId)}/reject`,
        body: { ...body, patch_id: patchId, vulnerability_id: body.vulnerability_id },
        timeoutMs: AI_ENGINE_TIMEOUTS.approval,
        requestId: res.locals.requestId,
      });
      res.status(r.status).json(r.data);
    } catch (err) {
      emitAiEngineFailure(err, res);
    }
  })
);

// ---------------------------------------------------------------------------
// 9. GET /api/analytics and GET /api/analytics/:experimentId
// ---------------------------------------------------------------------------
router.get(
  '/analytics',
  asyncHandler(async (req: Request, res: Response) => {
    try {
      const r = await getService().proxy({
        method: 'GET',
        path: '/api/analytics/latest/charts',
        timeoutMs: AI_ENGINE_TIMEOUTS.read,
        requestId: res.locals.requestId,
      });
      res.status(r.status).json(r.data);
    } catch (err) {
      emitAiEngineFailure(err, res);
    }
  })
);

router.get(
  '/analytics/:experimentId',
  asyncHandler(async (req: Request, res: Response) => {
    try {
      const r = await getService().proxy({
        method: 'GET',
        path: `/api/analytics/${encodeURIComponent(req.params.experimentId)}/charts`,
        timeoutMs: AI_ENGINE_TIMEOUTS.read,
        requestId: res.locals.requestId,
      });
      res.status(r.status).json(r.data);
    } catch (err) {
      emitAiEngineFailure(err, res);
    }
  })
);

// ---------------------------------------------------------------------------
// 10. GET /api/alerts — proxy to AI engine runtime monitoring alerts
// ---------------------------------------------------------------------------
router.get(
  '/alerts',
  asyncHandler(async (req: Request, res: Response) => {
    const severity = typeof req.query.severity === 'string' ? req.query.severity : undefined;
    const limitRaw = typeof req.query.limit === 'string' ? req.query.limit : undefined;
    const limit = limitRaw ? parseInt(limitRaw, 10) : undefined;

    try {
      const r = await getService().proxy({
        method: 'GET',
        path: '/api/v1/monitoring/alerts',
        query: {
          severity,
          limit: Number.isFinite(limit) && limit ? limit : undefined,
        },
        timeoutMs: AI_ENGINE_TIMEOUTS.read,
        requestId: res.locals.requestId,
      });
      res.status(r.status).json(r.data);
    } catch (err) {
      emitAiEngineFailure(err, res);
    }
  })
);

router.get(
  '/monitoring/events',
  asyncHandler(async (req: Request, res: Response) => {
    const eventType = typeof req.query.event_type === 'string' ? req.query.event_type : undefined;
    const severity = typeof req.query.severity === 'string' ? req.query.severity : undefined;
    const limit = typeof req.query.limit === 'string' ? Number.parseInt(req.query.limit, 10) : undefined;
    try {
      const r = await getService().proxy({
        method: 'GET',
        path: '/api/v1/monitoring/events',
        query: { event_type: eventType, severity, limit: Number.isFinite(limit) ? limit : undefined },
        timeoutMs: AI_ENGINE_TIMEOUTS.read,
        requestId: res.locals.requestId,
      });
      res.status(r.status).json(r.data);
    } catch (err) {
      emitAiEngineFailure(err, res);
    }
  })
);

router.get(
  '/monitoring/summary',
  asyncHandler(async (_req: Request, res: Response) => {
    try {
      const r = await getService().proxy({
        method: 'GET',
        path: '/api/v1/monitoring/summary',
        timeoutMs: AI_ENGINE_TIMEOUTS.read,
        requestId: res.locals.requestId,
      });
      res.status(r.status).json(r.data);
    } catch (err) {
      emitAiEngineFailure(err, res);
    }
  })
);

router.get(
  '/learning/summary',
  asyncHandler(async (_req: Request, res: Response) => {
    try {
      const r = await getService().proxy({
        method: 'GET',
        path: '/api/v1/learning/summary',
        timeoutMs: AI_ENGINE_TIMEOUTS.read,
        requestId: res.locals.requestId,
      });
      res.status(r.status).json(r.data);
    } catch (err) {
      emitAiEngineFailure(err, res);
    }
  })
);

// ---------------------------------------------------------------------------
// AI engine connectivity indicator
// ---------------------------------------------------------------------------
router.get(
  '/ai-engine/health',
  asyncHandler(async (req: Request, res: Response) => {
    try {
      const r = await getService().proxy({
        method: 'GET',
        path: '/api/v1/health',
        timeoutMs: AI_ENGINE_TIMEOUTS.read,
        requestId: res.locals.requestId,
      });
      res.status(r.status).json({
        success: r.ok,
        aiEngineReachable: r.ok,
        ...(typeof r.data === 'object' && r.data !== null ? r.data : {}),
        requestId: res.locals.requestId,
      });
    } catch (err) {
      if (err instanceof AiEngineConnectionError) {
        res.status(err.status).json({
          success: false,
          aiEngineReachable: false,
          error: err.message,
          code: err.code,
          requestId: res.locals.requestId,
        });
        return;
      }
      emitAiEngineFailure(err, res);
    }
  })
);

export const orchestrationRouter = router;