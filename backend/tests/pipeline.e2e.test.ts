import request from 'supertest';
import fs from 'fs';
import path from 'path';
import { createApp } from '../src/app';
import { AiEngineClient } from '../src/services/aiEngine.client';
import { OrchestrationService } from '../src/services/orchestration.service';
import { setOrchestrationServiceForTesting } from '../src/routes/orchestration.router';
import { WorkspaceService } from '../src/services/workspace.service';

class FakeAiEngineClient {
  calls: any[] = [];
  responses: Record<string, any> = {};

  constructor(responses: Record<string, any> = {}) {
    this.responses = responses;
  }

  async request<T = any>(opts: any): Promise<any> {
    this.calls.push(opts);
    if (opts.path.includes('/security/scan') && opts.body?.workspace_path?.includes('patched')) {
      const rescanResponse = this.responses['/security/rescan'];
      if (rescanResponse) return rescanResponse;
    }
    for (const [pattern, resp] of Object.entries(this.responses)) {
      if (opts.path.includes(pattern)) {
        return resp;
      }
    }
    return { status: 200, ok: true, data: {} };
  }
}

async function pollScan(app: any, repoId: string, scanId: string, timeoutMs = 6000): Promise<any> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const res = await request(app).get(`/api/repositories/${repoId}/scan/${scanId}/status`);
    if (res.body.status === 'COMPLETED' || res.body.status === 'FAILED') {
      return res.body;
    }
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`Scan ${scanId} did not settle in ${timeoutMs}ms`);
}

describe('End-to-End Security Pipeline & Remediation Flow', () => {
  const testWorkspaceDir = path.resolve(__dirname, '../uploads/test_pipeline_e2e');

  beforeAll(() => {
    WorkspaceService.setRootOverrideForTesting(testWorkspaceDir);
    fs.mkdirSync(testWorkspaceDir, { recursive: true });
  });

  afterAll(() => {
    WorkspaceService.setRootOverrideForTesting(null);
    if (fs.existsSync(testWorkspaceDir)) {
      fs.rmSync(testWorkspaceDir, { recursive: true, force: true });
    }
  });

  it('Test A: Single clean source file upload -> 10-stage scan -> certified secure download', async () => {
    const fakeAi = new FakeAiEngineClient({
      '/analyzer/analyze': {
        status: 200,
        ok: true,
        data: { languages: { python: 1.0 }, total_files: 1, symbols: [] },
      },
      '/hallucination/detect': {
        status: 200,
        ok: true,
        data: { findings: [], total_hallucinations: 0 },
      },
      '/security/scan': {
        status: 200,
        ok: true,
        data: { findings: [], total_vulnerabilities: 0 },
      },
      '/risk/assess': {
        status: 200,
        ok: true,
        data: {
          risk_assessment: {
            overall_risk_score: 0,
            overall_risk_level: 'LOW',
            total_findings: 0,
          },
        },
      },
    });

    setOrchestrationServiceForTesting(new OrchestrationService(fakeAi as unknown as AiEngineClient));
    const app = createApp();

    // 1. Upload single Python file
    const cleanSource = 'def add(a: int, b: int) -> int:\n    return a + b\n';
    const uploadRes = await request(app)
      .post('/api/repositories/upload')
      .attach('file', Buffer.from(cleanSource), 'add.py');

    expect(uploadRes.status).toBe(201);
    expect(uploadRes.body.success).toBe(true);
    expect(uploadRes.body.repository.uploadType).toBe('single_file');
    expect(uploadRes.body.repository.originalFileName).toBe('add.py');
    const repoId = uploadRes.body.repository.id;

    // 2. Start Scan
    const scanStartRes = await request(app)
      .post(`/api/repositories/${repoId}/scan`)
      .send();

    expect(scanStartRes.status).toBe(202);
    expect(scanStartRes.body.success).toBe(true);
    const scanId = scanStartRes.body.scanId;

    // 3. Poll Scan until completion
    const finalStatus = await pollScan(app, repoId, scanId);
    expect(finalStatus.status).toBe('COMPLETED');
    expect(finalStatus.stages.repository.state).toBe('COMPLETED');
    expect(finalStatus.stages.analysis.state).toBe('COMPLETED');
    expect(finalStatus.stages.hallucination.state).toBe('COMPLETED');
    expect(finalStatus.stages.dependency.state).toBe('NOT_APPLICABLE');
    expect(finalStatus.stages.security.state).toBe('COMPLETED');
    expect(finalStatus.stages.risk.state).toBe('COMPLETED');
    expect(finalStatus.stages.patch.state).toBe('NOT_APPLICABLE');
    expect(finalStatus.stages.validation.state).toBe('NOT_APPLICABLE');
    expect(finalStatus.stages.confidence.state).toBe('NOT_APPLICABLE');
    expect(finalStatus.stages.runtime.state).toBe('NOT_APPLICABLE');
    expect(finalStatus.stages.securedFile.state).toBe('COMPLETED');
    expect(finalStatus.confidence).toBeUndefined();
    expect(finalStatus.hasOutputFile).toBe(true);
    expect(finalStatus.downloadUrl).toBe(`/api/repositories/${repoId}/scan/${scanId}/download`);

    // 4. Download secured output file
    const downloadRes = await request(app)
      .get(`/api/repositories/${repoId}/scan/${scanId}/download`)
      .buffer();

    expect(downloadRes.status).toBe(200);
    expect(downloadRes.headers['content-disposition']).toContain('attachment');
    expect(downloadRes.headers['content-disposition']).toContain('add_secured.py');
    expect(downloadRes.body.toString('utf8')).toContain('def add(a: int, b: int)');
  });

  it.each(['FAILED', 'TIMEOUT'])('blocks secured output when the security scanner is %s', async (scannerStatus) => {
    const fakeAi = new FakeAiEngineClient({
      '/security/scan': {
        status: 200,
        ok: true,
        data: {
          status: 'NOT_APPLICABLE',
          scanner_status: scannerStatus,
          error: `Semgrep ${scannerStatus.toLowerCase()}`,
          findings: [],
        },
      },
    });
    setOrchestrationServiceForTesting(new OrchestrationService(fakeAi as unknown as AiEngineClient));
    const app = createApp();
    const uploadRes = await request(app)
      .post('/api/repositories/upload')
      .attach('file', Buffer.from('def add(a, b): return a + b\n'), `scanner-${scannerStatus.toLowerCase()}.py`);
    const repositoryId = uploadRes.body.repository.id;
    const startRes = await request(app).post(`/api/repositories/${repositoryId}/scan`).send();
    const finalStatus = await pollScan(app, repositoryId, startRes.body.scanId);

    expect(finalStatus.status).toBe('FAILED');
    expect(finalStatus.stages.security.state).toBe('FAILED');
    expect(finalStatus.stages.securedFile.state).toBe('SKIPPED');
    expect(finalStatus.hasOutputFile).toBe(false);
  });

  it('blocks secured output when the final security re-scan times out', async () => {
    const fakeAi = new FakeAiEngineClient({
      '/security/scan': {
        status: 200,
        ok: true,
        data: {
          status: 'COMPLETED',
          scanner_status: 'COMPLETED',
          findings: [{ id: 'rescan-vuln', type: 'SQL Injection', severity: 'HIGH', file: 'query.py', line: 1 }],
        },
      },
      '/security/rescan': {
        status: 200,
        ok: true,
        data: { status: 'NOT_APPLICABLE', scanner_status: 'TIMEOUT', error: 'Semgrep timed out', findings: [] },
      },
      '/generate-patches': {
        status: 200,
        ok: true,
        data: { candidates: [{ patch_id: 'timeout-test-patch', modified_code: 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))' }] },
      },
      '/validate-candidates': {
        status: 200,
        ok: true,
        data: { results: [{ patch_id: 'timeout-test-patch', validation_status: 'SUCCESS' }] },
      },
      '/recommendation': {
        status: 200,
        ok: true,
        data: { recommendation: { recommended_patch_id: 'timeout-test-patch', highest_confidence_score: 90, ranked_patches: [{ patch_id: 'timeout-test-patch', confidence_score: 90 }] } },
      },
    });
    setOrchestrationServiceForTesting(new OrchestrationService(fakeAi as unknown as AiEngineClient));
    const app = createApp();
    const uploadRes = await request(app)
      .post('/api/repositories/upload')
      .attach('file', Buffer.from('cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'), 'query.py');
    const repositoryId = uploadRes.body.repository.id;
    const startRes = await request(app).post(`/api/repositories/${repositoryId}/scan`).send();
    const finalStatus = await pollScan(app, repositoryId, startRes.body.scanId);

    expect(finalStatus.status).toBe('COMPLETED');
    expect(finalStatus.stages.security.state).toBe('COMPLETED');
    expect(finalStatus.stages.validation.state).toBe('COMPLETED');
    expect(finalStatus.stages.confidence.state).toBe('COMPLETED');
    expect(finalStatus.confidence).toBe(90);
    // Security verification could not be completed (rescan timed out): the
    // artifact cannot be claimed secured, so it is an explicitly unverified
    // download that requires acknowledgement — even with a high ACE score.
    expect(finalStatus.stages.securedFile.state).toBe('COMPLETED');
    expect(finalStatus.artifactAuthorization).toBe('UNVERIFIED_DOWNLOAD');
    expect(finalStatus.securityVerdict).toBe('UNVERIFIED');
    expect(finalStatus.downloadEligibility).toMatchObject({
      eligible: true,
      level: 'UNVERIFIED_DOWNLOAD',
      acknowledgementRequired: true,
      securityGatesPassed: false,
      aceScore: 90,
    });
    expect(finalStatus.hasOutputFile).toBe(true);

    // Download without acknowledgement is refused.
    const denied = await request(app)
      .get(`/api/repositories/${repositoryId}/scan/${startRes.body.scanId}/download`);
    expect(denied.status).toBe(403);
    expect(denied.body.acknowledgementRequired).toBe(true);

    // Record the explicit, auditable acknowledgement.
    const ackRes = await request(app)
      .post(`/api/repositories/${repositoryId}/scan/${startRes.body.scanId}/acknowledge-download`)
      .send({ acknowledged: true, userId: 'dev-1' });
    expect(ackRes.status).toBe(200);
    expect(ackRes.body.acknowledged).toBe(true);

    // Download after acknowledgement delivers the scanned candidate.
    const downloadRes = await request(app)
      .get(`/api/repositories/${repositoryId}/scan/${startRes.body.scanId}/download?acknowledge=true`)
      .buffer();
    expect(downloadRes.status).toBe(200);
    expect(downloadRes.headers['content-disposition']).toContain('attachment');
    expect(downloadRes.headers['x-content-sha256']).toBeDefined();
    expect(downloadRes.body.toString('utf8')).toContain('cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))');
  });

  it('unverified validation without a confidence recommendation is ineligible for download', async () => {
    const fakeAi = new FakeAiEngineClient({
      '/security/scan': {
        status: 200,
        ok: true,
        data: { status: 'COMPLETED', scanner_status: 'COMPLETED', findings: [{ id: 'unverified-vuln', type: 'SQL Injection', severity: 'HIGH', file: 'query.py', line: 1 }] },
      },
      '/generate-patches': {
        status: 200,
        ok: true,
        data: { candidates: [{ patch_id: 'unverified-patch', modified_code: 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))' }] },
      },
      '/validate-candidates': {
        status: 200,
        ok: true,
        data: { results: [{ patch_id: 'unverified-patch', validation_status: 'UNVERIFIED' }] },
      },
    });
    setOrchestrationServiceForTesting(new OrchestrationService(fakeAi as unknown as AiEngineClient));
    const app = createApp();
    const uploadRes = await request(app)
      .post('/api/repositories/upload')
      .attach('file', Buffer.from('cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'), 'query.py');
    const repositoryId = uploadRes.body.repository.id;
    const startRes = await request(app).post(`/api/repositories/${repositoryId}/scan`).send();
    const finalStatus = await pollScan(app, repositoryId, startRes.body.scanId);

    expect(finalStatus.status).toBe('COMPLETED');
    expect(finalStatus.stages.validation.state).toBe('COMPLETED');
    expect(finalStatus.stages.validation.details.unverifiedResults).toBe(1);
    // No recommendation was produced, so no ACE score exists. The pipeline
    // still produces a remediated artifact: missing ACE means unverified
    // download with explicit acknowledgement required (no score fabricated).
    expect(finalStatus.stages.confidence.state).toBe('FAILED');
    expect(finalStatus.stages.securedFile.state).toBe('COMPLETED');
    expect(finalStatus.securityVerdict).toBe('UNVERIFIED');
    expect(finalStatus.artifactAuthorization).toBe('UNVERIFIED_DOWNLOAD');
    expect(finalStatus.downloadEligibility).toMatchObject({
      eligible: true,
      level: 'UNVERIFIED_DOWNLOAD',
      acknowledgementRequired: true,
      aceScore: null,
    });
    expect(finalStatus.hasOutputFile).toBe(true);

    const denied = await request(app)
      .get(`/api/repositories/${repositoryId}/scan/${startRes.body.scanId}/download`);
    expect(denied.status).toBe(403);
    expect(denied.body.acknowledgementRequired).toBe(true);

    const ackRes = await request(app)
      .post(`/api/repositories/${repositoryId}/scan/${startRes.body.scanId}/acknowledge-download`)
      .send({ acknowledged: true, userId: 'dev-no-ace' });
    expect(ackRes.status).toBe(200);

    const downloadRes = await request(app)
      .get(`/api/repositories/${repositoryId}/scan/${startRes.body.scanId}/download?acknowledge=true`)
      .buffer();
    expect(downloadRes.status).toBe(200);
    expect(downloadRes.body.toString('utf8')).toContain('cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))');
  });

  it('denies download of a stale artifact when persisted authorization is blocked', async () => {
    const fakeAi = new FakeAiEngineClient({
      '/security/scan': {
        status: 200,
        ok: true,
        data: { status: 'NOT_APPLICABLE', scanner_status: 'FAILED', findings: [] },
      },
    });
    const service = new OrchestrationService(fakeAi as unknown as AiEngineClient);
    setOrchestrationServiceForTesting(service);
    const app = createApp();
    const uploadRes = await request(app)
      .post('/api/repositories/upload')
      .attach('file', Buffer.from('def clean(): return True\n'), 'clean.py');
    const repositoryId = uploadRes.body.repository.id;
    const startRes = await request(app).post(`/api/repositories/${repositoryId}/scan`).send();
    const scanId = startRes.body.scanId;
    const finalStatus = await pollScan(app, repositoryId, scanId);
    const scan = service.getScan(scanId)!;
    const staleFile = WorkspaceService.securedFilePath(scanId, 'stale.zip');
    fs.writeFileSync(staleFile, 'stale artifact');
    scan.outputFile = staleFile;
    scan.artifactAuthorization = 'BLOCKED';

    const statusRes = await request(app).get(`/api/repositories/${repositoryId}/scan/${scanId}/status`);
    const downloadRes = await request(app).get(`/api/repositories/${repositoryId}/scan/${scanId}/download`);

    expect(finalStatus.status).toBe('FAILED');
    expect(statusRes.body.artifactAuthorization).toBe('BLOCKED');
    expect(statusRes.body.hasOutputFile).toBe(false);
    expect(downloadRes.status).toBe(404);
  });

  it('Test B: Vulnerable source file -> residual findings block secured download', async () => {
    const fakeAi = new FakeAiEngineClient({
      '/analyzer/analyze': {
        status: 200,
        ok: true,
        data: { languages: { python: 1.0 } },
      },
      '/hallucination/detect': {
        status: 200,
        ok: true,
        data: { findings: [] },
      },
      '/security/scan': {
        status: 200,
        ok: true,
        data: {
          findings: [
            {
              id: 'vuln-sql-1',
              type: 'SQL Injection',
              severity: 'CRITICAL',
              file: 'query.py',
              line: 3,
              code: 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
              description: 'Untrusted user input concatenated directly into SQL query',
            },
          ],
        },
      },
      '/risk/assess': {
        status: 200,
        ok: true,
        data: {
          risk_assessment: {
            overall_risk_score: 85,
            overall_risk_level: 'CRITICAL',
            total_findings: 1,
          },
        },
      },
      '/generate-patches': {
        status: 200,
        ok: true,
        data: {
          vulnerability_id: 'vuln-sql-1',
          candidates: [
            {
              patch_id: 'patch-param-sql',
              modified_code: 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
              explanation: 'Parameterized parameterized query prevents SQL injection',
              security_strategy: 'Parameterized Query',
              assumptions: [],
              expected_effect: 'Safe query execution',
              potential_side_effects: [],
            },
          ],
        },
      },
      '/validate-candidates': {
        status: 200,
        ok: true,
        data: {
          results: [
            {
              patch_id: 'patch-param-sql',
              validation_status: 'SUCCESS',
              compilation_score: { score: 1.0 },
              unit_test_score: { score: 1.0 },
              security_score: { score: 1.0 },
              functional_score: { score: 1.0 },
              performance_score: { score: 1.0 },
              regression_score: { score: 1.0 },
            },
          ],
        },
      },
      '/recommendation': {
        status: 200,
        ok: true,
        data: {
          recommendation: {
            vulnerability_id: 'vuln-sql-1',
            recommended_patch_id: 'patch-param-sql',
            highest_confidence_score: 95.0,
            ranked_patches: [
              {
                rank: 1,
                patch_id: 'patch-param-sql',
                confidence_score: 95.0,
                meets_safety_threshold: true,
              },
            ],
          },
        },
      },
    });

    setOrchestrationServiceForTesting(new OrchestrationService(fakeAi as unknown as AiEngineClient));
    const app = createApp();

    // 1. Upload vulnerable Python file
    const vulnSource =
      'import sqlite3\ndef get_user(cursor, user_id):\n    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n    return cursor.fetchone()\n';
    const uploadRes = await request(app)
      .post('/api/repositories/upload')
      .attach('file', Buffer.from(vulnSource), 'query.py');

    expect(uploadRes.status).toBe(201);
    const repoId = uploadRes.body.repository.id;

    // 2. Start Scan
    const scanStartRes = await request(app)
      .post(`/api/repositories/${repoId}/scan`)
      .send();

    expect(scanStartRes.status).toBe(202);
    const scanId = scanStartRes.body.scanId;

    // 3. Poll Scan
    const finalStatus = await pollScan(app, repoId, scanId);
    expect(finalStatus.status).toBe('COMPLETED');
    expect(finalStatus.stages.security.state).toBe('COMPLETED');
    expect(finalStatus.stages.risk.state).toBe('COMPLETED');
    expect(finalStatus.stages.patch.state).toBe('COMPLETED');
    expect(finalStatus.stages.validation.state).toBe('COMPLETED');
    expect(finalStatus.stages.confidence.state).toBe('COMPLETED');
    // The re-scan re-detects the CRITICAL vulnerability: fail-closed, no
    // downloadable artifact (not even unverified).
    expect(finalStatus.stages.securedFile.state).toBe('FAILED');
    expect(finalStatus.riskScore).toBe(85);
    expect(finalStatus.confidence).toBe(95);
    expect(finalStatus.securityVerdict).toBe('BLOCKED');
    expect(finalStatus.artifactAuthorization).toBe('BLOCKED');
    expect(finalStatus.downloadEligibility).toMatchObject({ eligible: false, level: 'INELIGIBLE' });
    expect(finalStatus.hasOutputFile).toBe(false);
    expect(finalStatus.stages.securedFile.error).toContain('Confirmed critical vulnerability');

    // The API must not offer an artifact while a confirmed critical vulnerability remains.
    const downloadRes = await request(app)
      .get(`/api/repositories/${repoId}/scan/${scanId}/download`)
      .buffer();

    expect(downloadRes.status).toBe(404);
  });
});
