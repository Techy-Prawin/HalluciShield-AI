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

  it('Test B: Vulnerable source file -> patch generation -> validation -> ranking -> remediated download', async () => {
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
    expect(finalStatus.stages.securedFile.state).toBe('COMPLETED');
    expect(finalStatus.riskScore).toBe(85);
    expect(finalStatus.confidence).toBe(95);
    expect(finalStatus.hasOutputFile).toBe(true);

    // 4. Download remediated file
    const downloadRes = await request(app)
      .get(`/api/repositories/${repoId}/scan/${scanId}/download`)
      .buffer();

    expect(downloadRes.status).toBe(200);
    expect(downloadRes.headers['content-disposition']).toContain('query_secured.py');
    expect(downloadRes.body.toString('utf8')).toContain('cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))');
  });
});
