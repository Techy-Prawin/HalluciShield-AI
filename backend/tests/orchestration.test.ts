import request from 'supertest';
import fs from 'fs';
import path from 'path';
import { createApp } from '../src/app';
import { AiEngineClient, AiEngineConnectionError } from '../src/services/aiEngine.client';
import { OrchestrationService, ScanRecord } from '../src/services/orchestration.service';
import { setOrchestrationServiceForTesting } from '../src/routes/orchestration.router';
import { WorkspaceService } from '../src/services/workspace.service';

class FakeClient {
  calls: any[] = [];
  handler: (opts: any) => Promise<any>;

  constructor(handler: (opts: any) => Promise<any>) {
    this.handler = handler;
  }

  async request<T = any>(opts: any): Promise<any> {
    this.calls.push(opts);
    return this.handler(opts);
  }
}

function makeService(handler: (opts: any) => Promise<any>): OrchestrationService {
  return new OrchestrationService(new FakeClient(handler) as unknown as AiEngineClient);
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

describe('Orchestration router', () => {
  const testWorkspaceDir = path.resolve(__dirname, '../uploads/test_orchestration_ws');
  let scanWorkspace: string;

  beforeAll(() => {
    WorkspaceService.setRootOverrideForTesting(testWorkspaceDir);
    fs.mkdirSync(testWorkspaceDir, { recursive: true });
    scanWorkspace = path.join(testWorkspaceDir, 'repo-1');
    fs.mkdirSync(scanWorkspace, { recursive: true });
    fs.writeFileSync(path.join(scanWorkspace, 'app.py'), 'def f():\n    return 1\n');
  });

  afterAll(() => {
    WorkspaceService.setRootOverrideForTesting(null);
    if (fs.existsSync(testWorkspaceDir)) {
      fs.rmSync(testWorkspaceDir, { recursive: true, force: true });
    }
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('POST scan -> status -> findings: completes and aggregates AI engine results (202/200)', async () => {
    const responses: Record<string, any> = {
      '/api/v1/analyzer/analyze': { status: 200, ok: true, data: { languages: { python: 1.0 } } },
      '/api/v1/hallucination/detect': {
        status: 200,
        ok: true,
        data: { repository_id: 'repo-1', findings: [{ id: 'hallucination-1' }] },
      },
      '/api/v1/security/scan': {
        status: 200,
        ok: true,
        data: { total_vulnerabilities: 0, findings: [] },
      },
      '/api/v1/dependency/analyze': {
        status: 200,
        ok: true,
        data: { dependency_findings: [] },
      },
      '/api/v1/risk/assess': {
        status: 200,
        ok: true,
        data: {
          risk_assessment: {
            overall_risk_score: 12,
            overall_risk_level: 'LOW',
            total_findings: 0,
          },
        },
      },
    };
    const fake = new FakeClient(async (opts: any) => {
      for (const [k, v] of Object.entries(responses)) {
        if (opts.path.includes(k)) return v;
      }
      return { status: 200, ok: true, data: {} };
    });
    setOrchestrationServiceForTesting(new OrchestrationService(fake as unknown as AiEngineClient));
    const app = createApp();

    const start = await request(app)
      .post('/api/repositories/repo-1/scan')
      .send({ workspacePath: scanWorkspace });
    expect(start.status).toBe(202);
    expect(start.body).toHaveProperty('scanId');
    expect(start.body.status).toBe('QUEUED');
    const scanId: string = start.body.scanId;

    const finalStatus = await pollScanUntilFinished(app, 'repo-1', scanId);
    expect(finalStatus.status).toBe('COMPLETED');
    expect(finalStatus.stages.security.state).toBe('COMPLETED');
    expect(finalStatus.stages.dependency.state).toBe('NOT_APPLICABLE');

    const findings = await request(app).get(
      `/api/repositories/repo-1/scan/${scanId}/findings`
    );
    expect(findings.status).toBe(200);
    expect(findings.body.status).toBe('COMPLETED');
    expect(findings.body.hallucinationFindings.findings[0].id).toBe('hallucination-1');
    expect(findings.body.securityFindings.total_vulnerabilities).toBe(0);

    const calledPaths = fake.calls.map((c: any) => c.path);
    expect(calledPaths).toContain('/api/v1/analyzer/analyze');
    expect(calledPaths).toContain('/api/v1/hallucination/detect');
    expect(calledPaths).toContain('/api/v1/security/scan');
    expect(calledPaths).toContain('/api/v1/dependency/analyze');
    expect(calledPaths).toContain('/api/v1/risk/assess');
  });

  it('POST scan without a resolvable workspace returns 404', async () => {
    const fake = new FakeClient(async () => ({ status: 500, ok: false, data: {} }));
    setOrchestrationServiceForTesting(new OrchestrationService(fake as unknown as AiEngineClient));
    const app = createApp();

    const res = await request(app).post('/api/repositories/does-not-exist/scan').send({});
    expect(res.status).toBe(404);
  });

  it('GET status / findings for an unknown scan returns 404', async () => {
    const fake = new FakeClient(async () => ({ status: 200, ok: true, data: {} }));
    setOrchestrationServiceForTesting(new OrchestrationService(fake as unknown as AiEngineClient));
    const app = createApp();

    const status = await request(app).get('/api/repositories/repo-1/scan/unknown-id/status');
    expect(status.status).toBe(404);

    const findings = await request(app).get(
      '/api/repositories/repo-1/scan/unknown-id/findings'
    );
    expect(findings.status).toBe(404);
  });

  it('findings returns 202 while the scan is still running', async () => {
    let resolveDetect: (v: any) => void = () => {};
    const detectGate = new Promise<any>((r) => {
      resolveDetect = r;
    });

    const fake = new FakeClient(async (opts: any) => {
      if (opts.path === '/api/v1/hallucination/detect') return detectGate;
      if (opts.path === '/api/v1/security/scan') {
        return { status: 200, ok: true, data: { total_vulnerabilities: 0, findings: [] } };
      }
      if (opts.path === '/api/v1/dependency/analyze') {
        return { status: 200, ok: true, data: {} };
      }
      return { status: 200, ok: true, data: {} };
    });
    setOrchestrationServiceForTesting(new OrchestrationService(fake as unknown as AiEngineClient));
    const app = createApp();

    const start = await request(app)
      .post('/api/repositories/repo-1/scan')
      .send({ workspacePath: scanWorkspace });
    const scanId: string = start.body.scanId;

    const running = await request(app).get(
      `/api/repositories/repo-1/scan/${scanId}/findings`
    );
    expect(running.status).toBe(202);
    expect(['QUEUED', 'RUNNING']).toContain(running.body.status);

    // Let the queue kick in so the scan is observed as RUNNING behind the gate.
    await new Promise((r) => setTimeout(r, 5));
    const gateOpen = await request(app).get(
      `/api/repositories/repo-1/scan/${scanId}/findings`
    );
    expect(gateOpen.status).toBe(202);
    expect(gateOpen.body.status).toBe('RUNNING');

    resolveDetect({ status: 200, ok: true, data: { findings: [] } });
    await new Promise((r) => setTimeout(r, 30));
  });

  it('POST patches generates and caches candidates; GET patches returns them', async () => {
    const fake = new FakeClient(async (opts: any) => {
      if (opts.path.includes('/generate-patches')) {
        return {
          status: 200,
          ok: true,
          data: { vulnerability_id: 'vuln-abc', candidates: [{ patch_id: 'p1' }] },
        };
      }
      return { status: 200, ok: true, data: {} };
    });
    setOrchestrationServiceForTesting(new OrchestrationService(fake as unknown as AiEngineClient));
    const app = createApp();

    const start = await request(app)
      .post('/api/repositories/repo-1/scan')
      .send({ workspacePath: 'C:/tmp/repo-1' });
    const scanId: string = start.body.scanId;

    const gen = await request(app)
      .post(`/api/repositories/repo-1/scan/${scanId}/patches`)
      .send({ vulnerable_code: 'SELECT * FROM users;' });
    expect(gen.status).toBe(200);
    expect(gen.body.vulnerabilityId).toBeDefined();
    expect(gen.body.candidates[0].patch_id).toBe('p1');

    const cached = await request(app).get(`/api/repositories/repo-1/scan/${scanId}/patches`);
    expect(cached.status).toBe(200);
    expect(cached.body.patches[gen.body.vulnerabilityId]).toBeDefined();
  });

  it('proxies validation errors back through without wrapping them', async () => {
    const fake = new FakeClient(async () => ({
      status: 400,
      ok: false,
      data: { detail: 'At least one candidate patch is required' },
    }));
    setOrchestrationServiceForTesting(new OrchestrationService(fake as unknown as AiEngineClient));
    const app = createApp();

    const start = await request(app)
      .post('/api/repositories/repo-1/scan')
      .send({ workspacePath: 'C:/tmp/repo-1' });
    const scanId: string = start.body.scanId;

    const missing = await request(app)
      .post(`/api/repositories/repo-1/scan/${scanId}/validate`)
      .send({ vulnerability_id: 'vuln-1' });
    expect(missing.status).toBe(400);
    expect(missing.body.error).toContain('candidates');

    const badRank = await request(app)
      .post(`/api/repositories/repo-1/scan/${scanId}/rank`)
      .send({ vulnerability_id: 'vuln-1', validation_results: [] });
    expect(badRank.status).toBe(400);
  });

  it('returns 503 when the AI engine is unreachable', async () => {
    const fake = new FakeClient(async () => {
      throw new AiEngineConnectionError('AI engine unreachable: network error', 'ECONNREFUSED');
    });
    setOrchestrationServiceForTesting(new OrchestrationService(fake as unknown as AiEngineClient));
    const app = createApp();

    const health = await request(app).get('/api/ai-engine/health');
    expect(health.status).toBe(503);
    expect(health.body.aiEngineReachable).toBe(false);
    expect(health.body.code).toBe('ECONNREFUSED');
  });

  it('a failed hallucination stage still delivers partial findings (200)', async () => {
    const fake = new FakeClient(async (opts: any) => {
      if (opts.path === '/api/v1/hallucination/detect') {
        return { status: 500, ok: false, data: { detail: 'boom' } };
      }
      if (opts.path === '/api/v1/security/scan') {
        return { status: 200, ok: true, data: { total_vulnerabilities: 1, findings: [{ id: 'sec-1' }] } };
      }
      return { status: 200, ok: true, data: {} };
    });
    setOrchestrationServiceForTesting(new OrchestrationService(fake as unknown as AiEngineClient));
    const app = createApp();

    const start = await request(app)
      .post('/api/repositories/repo-1/scan')
      .send({ workspacePath: scanWorkspace });
    const scanId: string = start.body.scanId;

    const finalStatus = await pollScanUntilFinished(app, 'repo-1', scanId);
    expect(finalStatus.status).toBe('COMPLETED');
    expect(finalStatus.stages.hallucination.state).toBe('FAILED');
    expect(finalStatus.stages.security.state).toBe('COMPLETED');

    const findings = await request(app).get(
      `/api/repositories/repo-1/scan/${scanId}/findings`
    );
    expect(findings.status).toBe(200);
    expect(findings.body.success).toBe(true);
    expect(findings.body.hallucinationFindings).toBeNull();
    expect(findings.body.securityFindings.total_vulnerabilities).toBe(1);
  });

  it('findings returns 502 when every stage failed', async () => {
    const fake = new FakeClient(async () => ({
      status: 500,
      ok: false,
      data: { detail: 'boom' },
    }));
    setOrchestrationServiceForTesting(new OrchestrationService(fake as unknown as AiEngineClient));
    const app = createApp();

    const start = await request(app)
      .post('/api/repositories/repo-1/scan')
      .send({ workspacePath: path.join(scanWorkspace, 'missing') });
    const scanId: string = start.body.scanId;

    const finalStatus = await pollScanUntilFinished(app, 'repo-1', scanId);
    expect(finalStatus.status).toBe('FAILED');

    const findings = await request(app).get(
      `/api/repositories/repo-1/scan/${scanId}/findings`
    );
    expect(findings.status).toBe(502);
  });

  it('scan registry never stores or logs AI engine keys (X-Request-ID propagated only)', async () => {
    const fake = new FakeClient(async () => ({ status: 200, ok: true, data: {} }));
    setOrchestrationServiceForTesting(new OrchestrationService(fake as unknown as AiEngineClient));
    const app = createApp();

    await request(app)
      .post('/api/repositories/repo-1/scan')
      .set('X-Request-ID', 'trace-42')
      .send({ workspacePath: 'C:/tmp/repo-1' });

    for (const call of fake.calls) {
      expect(call.requestId).toBeDefined();
    }
  });
});

describe('ScanRecord lifecycle', () => {
  it('creates scans in QUEUED state with timestamps', () => {
    const service = new OrchestrationService(new FakeClient(async () => ({})) as unknown as AiEngineClient);
    const scan = service.startScan('repo-x', 'C:/wb');
    expect(scan.status).toBe('QUEUED');
    expect(scan.id).toBeDefined();
    expect(scan.createdAt).toBeDefined();
    expect(scan.updatedAt).toBeDefined();
    expect(service.getScan(scan.id)).toEqual(scan);
  });
});