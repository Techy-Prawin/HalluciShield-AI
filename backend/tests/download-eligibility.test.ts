import request from 'supertest';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { createApp } from '../src/app';
import { AiEngineClient } from '../src/services/aiEngine.client';
import { OrchestrationService } from '../src/services/orchestration.service';
import { setOrchestrationServiceForTesting } from '../src/routes/orchestration.router';
import { WorkspaceService } from '../src/services/workspace.service';
import AdmZip from 'adm-zip';

/** Stateful fake AI engine. Each route pattern gets an ordered list of
 * responses; consecutive calls to the same path consume them in order.
 * Mirrors the real ai-engine endpoints the orchestration service calls. */
class StatefulFakeAiEngine {
  private calls = new Map<string, number>();
  constructor(private routes: Record<string, { responses: any[] }>) {}
  async request(opts: any): Promise<any> {
    const count = (this.calls.get(opts.path) ?? 0) + 1;
    this.calls.set(opts.path, count);
    for (const [pattern, route] of Object.entries(this.routes)) {
      if (opts.path.includes(pattern)) {
        const response = route.responses[Math.min(count - 1, route.responses.length - 1)];
        const payload = response && typeof response === 'object' && response.data !== undefined ? response.data : response;
        const status = typeof response?.status === 'number' ? response.status : 200;
        const ok = response?.ok !== false && status < 400;
        if (!ok) return { status, ok: false, data: payload };
        return { status, ok: true, data: payload };
      }
    }
    return { status: 200, ok: true, data: {} };
  }
}

function makeRoutes(overrides: {
  securityFinding?: any;
  securityStatus?: string;
  securityScannerStatus?: string;
  validationStatus?: 'SUCCESS' | 'UNVERIFIED' | 'FAILED';
  sandboxStatus?: string;
  aceScore?: number | null;
  rescanFindings?: any[];
  rescanStatus?: string;
  rescanScannerStatus?: string;
}) {
  const {
    securityFinding = { id: 'app-vuln', type: 'SQL Injection', severity: 'HIGH', file: 'app.py', line: 4, code_snippet: 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)' },
    securityStatus = 'COMPLETED',
    securityScannerStatus = 'COMPLETED',
    validationStatus = 'SUCCESS',
    sandboxStatus = 'AVAILABLE',
    aceScore = 88,
    rescanFindings = [],
    rescanStatus = 'COMPLETED',
    rescanScannerStatus = 'COMPLETED',
  } = overrides;

  const findingCopy = { ...securityFinding };
  const rescanningSecurity = {
    status: rescanStatus,
    scanner_status: rescanScannerStatus,
    findings: rescanFindings,
    ...(rescanScannerStatus === 'TIMEOUT' ? { error: 'Semgrep timed out' } : {}),
  };

  return {
    '/analyzer/analyze': {
      responses: [{ data: { languages: { python: 1.0 }, total_files: 1, symbols: [] } }],
    },
    '/hallucination/detect': {
      responses: [
        { data: { findings: [], total_hallucinations: 0 } },
        { data: { findings: [] } },
      ],
    },
    '/security/scan': {
      responses: [
        { data: { status: securityStatus, scanner_status: securityScannerStatus, findings: [findingCopy] } },
        rescanningSecurity,
      ],
    },
    '/risk/assess': {
      responses: [{ data: { risk_assessment: { overall_risk_score: 25, overall_risk_level: 'LOW', total_findings: 1 } } }],
    },
    '/vulnerabilities/app-vuln/generate-patches': {
      responses: [{
        data: {
          candidates: [
            {
              patch_id: 'app-patch-1',
              file: 'app.py',
              modified_code: 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            },
          ],
        },
      }],
    },
    '/vulnerabilities/app-vuln/validate-candidates': {
      responses: [{
        data: {
          results: [
            {
              patch_id: 'app-patch-1',
              validation_status: validationStatus,
              ...(sandboxStatus ? { sandbox_status: sandboxStatus } : {}),
            },
          ],
        },
      }],
    },
    '/vulnerabilities/app-vuln/recommendation': {
      responses: [{
        data: {
          recommendation: {
            recommended_patch_id: 'app-patch-1',
            highest_confidence_score: aceScore,
            ranked_patches: aceScore === null
              ? [{ patch_id: 'app-patch-1' }]
              : [{ patch_id: 'app-patch-1', confidence_score: aceScore }],
          },
        },
      }],
    },
    '/runtime/monitor': {
      responses: [{ data: { status: 'ok' } }],
    },
  };
}

async function uploadAndScan(app: any, fileName: string, content: Buffer, zip = false) {
  const uploadRes = await request(app)
    .post('/api/repositories/upload')
    .attach('file', content, fileName);
  expect(uploadRes.status).toBe(201);
  const repositoryId = uploadRes.body.repository.id;
  const startRes = await request(app).post(`/api/repositories/${repositoryId}/scan`).send();
  return { repositoryId, scanId: startRes.body.scanId };
}

async function pollScan(app: any, repoId: string, scanId: string, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const res = await request(app).get(`/api/repositories/${repoId}/scan/${scanId}/status`);
    if (res.body.status === 'COMPLETED' || res.body.status === 'FAILED') return res.body;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`Scan ${scanId} did not settle`);
}

function sha256(buffer: Buffer): string {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

const testWorkspaceDir = path.resolve(__dirname, '../uploads/test_download_eligibility');

describe('ACE-based download eligibility (download_eligibility vs security_verdict)', () => {
  let service: OrchestrationService;

  beforeAll(() => {
    WorkspaceService.setRootOverrideForTesting(testWorkspaceDir);
    fs.mkdirSync(testWorkspaceDir, { recursive: true });
  });

  afterAll(() => {
    WorkspaceService.setRootOverrideForTesting(null);
    if (fs.existsSync(testWorkspaceDir)) fs.rmSync(testWorkspaceDir, { recursive: true, force: true });
  });

  beforeEach(() => {
    service = new OrchestrationService(new StatefulFakeAiEngine({}) as unknown as AiEngineClient);
    setOrchestrationServiceForTesting(service);
  });

  afterEach(() => {
    setOrchestrationServiceForTesting(service);
  });

  it('ACE >= 80 with all gates passing: authorized download, no acknowledgement needed', async () => {
    const app = createApp();
    const routes = makeRoutes({ aceScore: 88 });
    service = new OrchestrationService(new StatefulFakeAiEngine(routes) as unknown as AiEngineClient);
    setOrchestrationServiceForTesting(service);

    const appCode = 'import os\n\ndef get_user(user_id):\n    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n    return cursor.fetchone()\n';
    const zip = new AdmZip();
    zip.addFile('app.py', Buffer.from(appCode, 'utf8'));
    const { repositoryId, scanId } = await uploadAndScan(app, 'repo.zip', zip.toBuffer(), true);

    const finalStatus = await pollScan(app, repositoryId, scanId);
    expect(finalStatus.status).toBe('COMPLETED');
    expect(finalStatus.confidence).toBe(88);
    expect(finalStatus.securityVerdict).toBe('PASSED');
    expect(finalStatus.artifactAuthorization).toBe('AUTHORIZED');
    expect(finalStatus.downloadEligibility).toMatchObject({
      eligible: true,
      level: 'AUTHORIZED',
      acknowledgementRequired: false,
      aceScore: 88,
      aceScale: { min: 0, max: 100 },
      securityGatesPassed: true,
      thresholds: { authorized: 80, unverified: 60 },
    });
    expect(finalStatus.hasOutputFile).toBe(true);

    const record = service.getScan(scanId)!;
    expect(record.outputFileHash).toBeDefined();

    const downloadRes = await request(app)
      .get(`/api/repositories/${repositoryId}/scan/${scanId}/download`)
      .buffer();
    expect(downloadRes.status).toBe(200);
    expect(downloadRes.headers['content-disposition']).toContain('attachment');
    expect(downloadRes.headers['x-content-sha256']).toBe(sha256(downloadRes.body));
    expect(downloadRes.headers['x-content-sha256']).toBe(record.outputFileHash);

    const downloadedZip = new AdmZip(downloadRes.body);
    const entry = downloadedZip.getEntry('app.py');
    expect(entry).toBeDefined();
    const entryContent = entry!.getData().toString('utf8');
    expect(entryContent).toContain('%s');
    expect(entryContent).not.toContain(' + user_id)');
  });

  it('ACE 60-79 with UNVERIFIED validation: explicitly unverified download, no acknowledgement required, never labeled PASSED', async () => {
    const app = createApp();
    const routes = makeRoutes({ validationStatus: 'UNVERIFIED', aceScore: 70 });
    service = new OrchestrationService(new StatefulFakeAiEngine(routes) as unknown as AiEngineClient);
    setOrchestrationServiceForTesting(service);

    const appCode = 'import os\n\ndef get_user(user_id):\n    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n    return cursor.fetchone()\n';
    const { repositoryId, scanId } = await uploadAndScan(app, 'app.py', Buffer.from(appCode, 'utf8'));

    const finalStatus = await pollScan(app, repositoryId, scanId);
    expect(finalStatus.status).toBe('COMPLETED');
    expect(finalStatus.stages.validation.state).toBe('COMPLETED');
    expect(finalStatus.stages.validation.details.unverifiedResults).toBe(1);
    expect(finalStatus.confidence).toBe(70);
    // Unverified is reported honestly: never SECURE / VERIFIED / PASSED.
    expect(finalStatus.securityVerdict).toBe('UNVERIFIED');
    expect(finalStatus.securityVerdict).not.toBe('PASSED');
    expect(finalStatus.artifactAuthorization).toBe('UNVERIFIED_DOWNLOAD');
    expect(finalStatus.downloadEligibility).toMatchObject({
      eligible: true,
      level: 'UNVERIFIED_DOWNLOAD',
      acknowledgementRequired: false,
      aceScore: 70,
      securityGatesPassed: true,
    });
    expect(finalStatus.hasOutputFile).toBe(true);

    const downloadRes = await request(app)
      .get(`/api/repositories/${repositoryId}/scan/${scanId}/download`)
      .buffer();
    expect(downloadRes.status).toBe(200);
    expect(downloadRes.body.toString('utf8')).toContain('cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))');
  });

  it('ACE < 60: unverified download only with explicit acknowledgement', async () => {
    const app = createApp();
    const routes = makeRoutes({ aceScore: 45 });
    service = new OrchestrationService(new StatefulFakeAiEngine(routes) as unknown as AiEngineClient);
    setOrchestrationServiceForTesting(service);

    const appCode = 'import os\n\ndef get_user(user_id):\n    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n    return cursor.fetchone()\n';
    const { repositoryId, scanId } = await uploadAndScan(app, 'app.py', Buffer.from(appCode, 'utf8'));

    const finalStatus = await pollScan(app, repositoryId, scanId);
    expect(finalStatus.confidence).toBe(45);
    expect(finalStatus.securityVerdict).toBe('UNVERIFIED');
    expect(finalStatus.artifactAuthorization).toBe('UNVERIFIED_DOWNLOAD');
    expect(finalStatus.downloadEligibility).toMatchObject({
      eligible: true,
      level: 'UNVERIFIED_DOWNLOAD',
      acknowledgementRequired: true,
      aceScore: 45,
      securityGatesPassed: true,
    });

    const denied = await request(app)
      .get(`/api/repositories/${repositoryId}/scan/${scanId}/download`);
    expect(denied.status).toBe(403);
    expect(denied.body.acknowledgementRequired).toBe(true);

    const ackRes = await request(app)
      .post(`/api/repositories/${repositoryId}/scan/${scanId}/acknowledge-download`)
      .send({ acknowledged: true, userId: 'dev-low-ace' });
    expect(ackRes.status).toBe(200);
    expect(ackRes.body.acknowledged).toBe(true);

    const downloadRes = await request(app)
      .get(`/api/repositories/${repositoryId}/scan/${scanId}/download?acknowledge=true`)
      .buffer();
    expect(downloadRes.status).toBe(200);
    expect(downloadRes.body.toString('utf8')).toContain('%s');
    const record = service.getScan(scanId)!;
    expect(downloadRes.headers['x-content-sha256']).toBe(record.outputFileHash);
  });

  it('Missing or invalid ACE score: no score is fabricated; acknowledgement required', async () => {
    const app = createApp();
    const routes = makeRoutes({ aceScore: null });
    service = new OrchestrationService(new StatefulFakeAiEngine(routes) as unknown as AiEngineClient);
    setOrchestrationServiceForTesting(service);

    const appCode = 'import os\n\ndef get_user(user_id):\n    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n    return cursor.fetchone()\n';
    const { repositoryId, scanId } = await uploadAndScan(app, 'app.py', Buffer.from(appCode, 'utf8'));

    const finalStatus = await pollScan(app, repositoryId, scanId);
    expect(finalStatus.confidence).toBeUndefined();
    expect(finalStatus.securityVerdict).toBe('UNVERIFIED');
    expect(finalStatus.artifactAuthorization).toBe('UNVERIFIED_DOWNLOAD');
    expect(finalStatus.downloadEligibility).toMatchObject({
      eligible: true,
      level: 'UNVERIFIED_DOWNLOAD',
      acknowledgementRequired: true,
      aceScore: null,
      aceScale: { min: 0, max: 100 },
      securityGatesPassed: true,
    });
    expect(finalStatus.downloadEligibility.reason).toContain('No valid ACE score');

    const denied = await request(app)
      .get(`/api/repositories/${repositoryId}/scan/${scanId}/download`);
    expect(denied.status).toBe(403);

    const ackRes = await request(app)
      .post(`/api/repositories/${repositoryId}/scan/${scanId}/acknowledge-download`)
      .send({ acknowledged: true, userId: 'dev-no-ace' });
    expect(ackRes.status).toBe(200);

    const downloadRes = await request(app)
      .get(`/api/repositories/${repositoryId}/scan/${scanId}/download?acknowledge=true`)
      .buffer();
    expect(downloadRes.status).toBe(200);
    expect(downloadRes.body.toString('utf8')).toContain('%s');
  });

  it('Security re-scan timeout / sandbox unavailable: unverified download, acknowledgement required even with high ACE', async () => {
    const app = createApp();
    const routes = makeRoutes({ aceScore: 92, rescanScannerStatus: 'TIMEOUT' });
    service = new OrchestrationService(new StatefulFakeAiEngine(routes) as unknown as AiEngineClient);
    setOrchestrationServiceForTesting(service);

    const appCode = 'import os\n\ndef get_user(user_id):\n    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n    return cursor.fetchone()\n';
    const { repositoryId, scanId } = await uploadAndScan(app, 'app.py', Buffer.from(appCode, 'utf8'));

    const finalStatus = await pollScan(app, repositoryId, scanId);
    expect(finalStatus.confidence).toBe(92);
    expect(finalStatus.securityVerdict).toBe('UNVERIFIED');
    expect(finalStatus.artifactAuthorization).toBe('UNVERIFIED_DOWNLOAD');
    expect(finalStatus.downloadEligibility).toMatchObject({
      eligible: true,
      level: 'UNVERIFIED_DOWNLOAD',
      acknowledgementRequired: true,
      aceScore: 92,
      securityGatesPassed: false,
    });
    expect(finalStatus.hasOutputFile).toBe(true);

    const denied = await request(app)
      .get(`/api/repositories/${repositoryId}/scan/${scanId}/download`);
    expect(denied.status).toBe(403);

    const ackRes = await request(app)
      .post(`/api/repositories/${repositoryId}/scan/${scanId}/acknowledge-download`)
      .send({ acknowledged: true, userId: 'dev-timeout' });
    expect(ackRes.status).toBe(200);

    const downloadRes = await request(app)
      .get(`/api/repositories/${repositoryId}/scan/${scanId}/download?acknowledge=true`)
      .buffer();
    expect(downloadRes.status).toBe(200);
    expect(downloadRes.body.toString('utf8')).toContain('%s');
  });

  it('Sandbox unavailable during validation: pipeline stays truthful and continues', async () => {
    const app = createApp();
    const routes = makeRoutes({ validationStatus: 'UNVERIFIED', sandboxStatus: 'NOT_AVAILABLE', aceScore: 78 });
    service = new OrchestrationService(new StatefulFakeAiEngine(routes) as unknown as AiEngineClient);
    setOrchestrationServiceForTesting(service);

    const appCode = 'import os\n\ndef get_user(user_id):\n    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n    return cursor.fetchone()\n';
    const { repositoryId, scanId } = await uploadAndScan(app, 'app.py', Buffer.from(appCode, 'utf8'));

    const finalStatus = await pollScan(app, repositoryId, scanId);
    expect(finalStatus.status).toBe('COMPLETED');
    expect(finalStatus.stages.validation.state).toBe('COMPLETED');
    expect(finalStatus.confidence).toBe(78);
    expect(finalStatus.securityVerdict).toBe('UNVERIFIED');
    expect(finalStatus.artifactAuthorization).toBe('UNVERIFIED_DOWNLOAD');
    expect(finalStatus.hasOutputFile).toBe(true);
  });

  it('Confirmed critical vulnerability remains: blocked, never authorized, never downloadable', async () => {
    const app = createApp();
    const routes = makeRoutes({ aceScore: 95, rescanFindings: [{ id: 'app-vuln', type: 'SQL Injection', severity: 'CRITICAL', file: 'app.py', line: 2 }] });
    service = new OrchestrationService(new StatefulFakeAiEngine(routes) as unknown as AiEngineClient);
    setOrchestrationServiceForTesting(service);

    const appCode = 'import os\n\ndef get_user(user_id):\n    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n    return cursor.fetchone()\n';
    const { repositoryId, scanId } = await uploadAndScan(app, 'app.py', Buffer.from(appCode, 'utf8'));

    const finalStatus = await pollScan(app, repositoryId, scanId);
    expect(finalStatus.status).toBe('COMPLETED');
    expect(finalStatus.confidence).toBe(95);
    expect(finalStatus.securityVerdict).toBe('BLOCKED');
    expect(finalStatus.artifactAuthorization).toBe('BLOCKED');
    expect(finalStatus.downloadEligibility).toMatchObject({
      eligible: false,
      level: 'INELIGIBLE',
      acknowledgementRequired: false,
    });
    expect(finalStatus.downloadEligibility.reason).toContain('Confirmed critical vulnerability');
    expect(finalStatus.hasOutputFile).toBe(false);
    expect(finalStatus.stages.securedFile.state).toBe('FAILED');

    const downloadRes = await request(app)
      .get(`/api/repositories/${repositoryId}/scan/${scanId}/download`);
    expect(downloadRes.status).toBe(404);
  });

  it('Malicious payload remains: blocked, never downloadable', async () => {
    const app = createApp();
    const routes = makeRoutes({ aceScore: 90, rescanFindings: [{ id: 'app-vuln', type: 'Malicious Payload', severity: 'MEDIUM', file: 'app.py', line: 2 }] });
    service = new OrchestrationService(new StatefulFakeAiEngine(routes) as unknown as AiEngineClient);
    setOrchestrationServiceForTesting(service);

    const appCode = 'import os\n\ndef get_user(user_id):\n    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n    return cursor.fetchone()\n';
    const { repositoryId, scanId } = await uploadAndScan(app, 'app.py', Buffer.from(appCode, 'utf8'));

    const finalStatus = await pollScan(app, repositoryId, scanId);
    expect(finalStatus.securityVerdict).toBe('BLOCKED');
    expect(finalStatus.artifactAuthorization).toBe('BLOCKED');
    expect(finalStatus.downloadEligibility).toMatchObject({ eligible: false, level: 'INELIGIBLE' });
    expect(finalStatus.hasOutputFile).toBe(false);

    const downloadRes = await request(app)
      .get(`/api/repositories/${repositoryId}/scan/${scanId}/download`);
    expect(downloadRes.status).toBe(404);
  });

  it('Unauthorized download requests: BLOCKED and PENDING artifacts are rejected', async () => {
    const app = createApp();
    const routes = makeRoutes({ securityScannerStatus: 'FAILED' });
    service = new OrchestrationService(new StatefulFakeAiEngine(routes) as unknown as AiEngineClient);
    setOrchestrationServiceForTesting(service);

    const { repositoryId, scanId } = await uploadAndScan(app, 'app.py', Buffer.from('print("hi")\n', 'utf8'));
    const finalStatus = await pollScan(app, repositoryId, scanId);
    expect(finalStatus.status).toBe('FAILED');
    expect(finalStatus.artifactAuthorization).toBe('BLOCKED');

    const downloadRes = await request(app)
      .get(`/api/repositories/${repositoryId}/scan/${scanId}/download`);
    expect(downloadRes.status).toBe(404);
  });

  it('Tampered candidate hash: download rejected with integrity failure', async () => {
    const app = createApp();
    const routes = makeRoutes({ aceScore: 88 });
    service = new OrchestrationService(new StatefulFakeAiEngine(routes) as unknown as AiEngineClient);
    setOrchestrationServiceForTesting(service);

    const appCode = 'import os\n\ndef get_user(user_id):\n    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n    return cursor.fetchone()\n';
    const { repositoryId, scanId } = await uploadAndScan(app, 'app.py', Buffer.from(appCode, 'utf8'));
    await pollScan(app, repositoryId, scanId);

    const record = service.getScan(scanId)!;
    expect(record.outputFileHash).toBeDefined();
    record.outputFileHash = 'tampered-hash-that-does-not-match';

    const downloadRes = await request(app)
      .get(`/api/repositories/${repositoryId}/scan/${scanId}/download`);
    expect(downloadRes.status).toBe(409);
    expect(downloadRes.body.code).toBe('ARTIFACT_TAMPERED');
  });
});
