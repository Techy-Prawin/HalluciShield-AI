import request from 'supertest';
import fs from 'fs';
import path from 'path';
import { createApp } from '../src/app';
import { AiEngineClient } from '../src/services/aiEngine.client';
import { OrchestrationService } from '../src/services/orchestration.service';
import { setOrchestrationServiceForTesting } from '../src/routes/orchestration.router';
import { WorkspaceService } from '../src/services/workspace.service';

/**
 * Deterministic AI-engine double. Stateful: the security stage is called once
 * up front (returns findings) and again as the post-patch re-scan (returns
 * whatever is configured as afterFindings). Patch generation is routed per
 * vulnerability id, and all other stages answer from static fixtures.
 */
class StatefulFakeAiEngine {
  calls: any[] = [];
  securityCalls = 0;

  // Stand-in for the real /security/scan stream after patch application.
  afterFindings: any[] = [];
  afterVulnerabilities = 0;

  beforeFindings: any[] = [];
  beforeVulnerabilities = 0;

  failAnalysis = false;

  patches: Record<string, any> = {};
  validation: Record<string, any> = {};
  recommendation: Record<string, any> = {};

  async request<T = any>(opts: any): Promise<any> {
    this.calls.push(opts);
    const body = opts.body ?? {};
    const p = opts.path;

    if (p.includes('/analyzer/analyze')) {
      return {
        status: 200,
        ok: true,
        data: { languages: { python: 1.0 }, total_files: 1, symbols: [] },
      };
    }
    if (p.includes('/hallucination/detect')) {
      return { status: 200, ok: true, data: { findings: [], total_hallucinations: 0 } };
    }
    if (p.includes('/dependency/analyze')) {
      return { status: 200, ok: true, data: { dependencies: [], total_dependencies: 0 } };
    }
    if (p.includes('/security/scan')) {
      this.securityCalls += 1;
      const scanNumber = this.securityCalls;
      if (scanNumber > 1) {
        return {
          status: 200,
          ok: true,
          data: { findings: this.afterFindings, total_vulnerabilities: this.afterVulnerabilities },
        };
      }
      return {
        status: 200,
        ok: true,
        data: { findings: (this as any).beforeFindings, total_vulnerabilities: (this as any).beforeVulnerabilities },
      };
    }
    if (p.includes('/risk/assess')) {
      return {
        status: 200,
        ok: true,
        data: {
          risk_assessment: {
            overall_risk_score: 60,
            overall_risk_level: 'HIGH',
            total_findings: 2,
          },
        },
      };
    }
    if (p.includes('/generate-patches')) {
      const vulnId = String(body.vulnerability_id ?? body.vulnerabilityId ?? '');
      const entry = this.patches[vulnId];
      if (!entry) return { status: 404, ok: false, data: { error: { message: 'no patches' } } };
      return { status: 200, ok: true, data: entry };
    }
    if (p.includes('/validate-candidates')) {
      const vulnId = String(body.vulnerability_id ?? body.vulnerabilityId ?? '');
      const entry = this.validation[vulnId];
      if (!entry) return { status: 404, ok: false, data: { error: { message: 'no validation' } } };
      return { status: 200, ok: true, data: entry };
    }
    if (p.includes('/recommendation')) {
      const vulnId = String(body.vulnerability_id ?? body.vulnerabilityId ?? '');
      const entry = this.recommendation[vulnId];
      if (!entry) return { status: 404, ok: false, data: { error: { message: 'no recommendation' } } };
      return { status: 200, ok: true, data: entry };
    }
    return { status: 404, ok: false, data: { error: { message: `unhandled route ${p}` } } };
  }
}

async function pollScan(app: any, repoId: string, scanId: string, timeoutMs = 10000): Promise<any> {
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

describe('Remediation & resilience scenarios (Phases 9-14)', () => {
  const testWorkspaceDir = path.resolve(__dirname, '../uploads/test_pipeline_scenarios');

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

  it('Multiple vulnerability classes funnel through vetting, patching, validation and re-scan comparison', async () => {
    const fakeAi = new StatefulFakeAiEngine();
    fakeAi.beforeFindings = [
      {
        id: 'vuln-cmd-1',
        vulnerability_type: 'Command Injection',
        severity: 'HIGH',
        file: 'app.py',
        line: 4,
        code_snippet: '    os.system(cmd)',
      },
      {
        id: 'vuln-xss-1',
        vulnerability_type: 'XSS',
        severity: 'MEDIUM',
        file: 'app.py',
        line: 6,
        code_snippet: '    return flask.render_template_string("<p>" + request.args.get("q") + "</p>")',
      },
    ];
    fakeAi.beforeVulnerabilities = 2;
    fakeAi.afterFindings = [];
    fakeAi.afterVulnerabilities = 0;

    fakeAi.patches['vuln-cmd-1'] = {
      patch_id: 'patch-cmd-1',
      candidates: [
        {
          candidate_id: 'patch-cmd-1-c0',
          modified_code: '    subprocess.run(["ls", request.args.get("path")], check=False)',
          strategy: 'sanitize',
          language: 'python',
        },
      ],
    };
    fakeAi.patches['vuln-xss-1'] = {
      patch_id: 'patch-xss-1',
      candidates: [
        {
          candidate_id: 'patch-xss-1-c0',
          modified_code: '    return flask.escape(request.args.get("q"))',
          strategy: 'sanitize',
          language: 'python',
        },
      ],
    };

    fakeAi.validation['vuln-cmd-1'] = {
      vulnerability_id: 'vuln-cmd-1',
      candidates: [
        {
          candidate_id: 'patch-cmd-1-c0',
          patch_id: 'patch-cmd-1',
          final_patch: '    subprocess.run(["ls", request.args.get("path")], check=False)',
          strategy: 'sanitize',
        },
      ],
      results: [
        {
          candidate_id: 'patch-cmd-1-c0',
          syntax_valid: true,
          semantics_verified: true,
          security_verified: true,
          verdict: 'PASS',
        },
      ],
      sandbox_status: 'SANDBOX_OFF' as string,
      sandbox_execution: null,
      passed_candidate_id: 'patch-cmd-1-c0',
      passed: true,
    };
    fakeAi.validation['vuln-xss-1'] = {
      vulnerability_id: 'vuln-xss-1',
      candidates: [
        {
          candidate_id: 'patch-xss-1-c0',
          patch_id: 'patch-xss-1',
          final_patch: '    return flask.escape(request.args.get("q"))',
          strategy: 'sanitize',
        },
      ],
      results: [
        {
          candidate_id: 'patch-xss-1-c0',
          syntax_valid: true,
          semantics_verified: true,
          security_verified: true,
          verdict: 'PASS',
        },
      ],
      sandbox_status: 'SANDBOX_OFF' as string,
      sandbox_execution: null,
      passed_candidate_id: 'patch-xss-1-c0',
      passed: true,
    };

    fakeAi.recommendation['vuln-cmd-1'] = {
      recommendation: {
        vulnerability_id: 'vuln-cmd-1',
        patch_id: 'patch-cmd-1',
        ranked_patches: [
          {
            candidate_id: 'patch-cmd-1-c0',
            confidence_score: 92,
            semantic_similarity: 0.9,
            security_delta: 0.95,
            test_delta: 0,
            recommended: true,
          },
        ],
      },
    };
    fakeAi.recommendation['vuln-xss-1'] = {
      recommendation: {
        vulnerability_id: 'vuln-xss-1',
        patch_id: 'patch-xss-1',
        ranked_patches: [
          {
            candidate_id: 'patch-xss-1-c0',
            confidence_score: 90,
            semantic_similarity: 0.89,
            security_delta: 0.94,
            test_delta: 0,
            recommended: true,
          },
        ],
      },
    };

    setOrchestrationServiceForTesting(new OrchestrationService(fakeAi as unknown as AiEngineClient));
    const app = createApp();

    const source = [
      'import os',
      'import flask',
      '',
      'def run(request):',
      '    cmd = "ls " + request.args.get("path")',
      '    os.system(cmd)',
      '    return flask.render_template_string("<p>" + request.args.get("q") + "</p>")',
      '',
    ].join('\n');

    const uploadRes = await request(app)
      .post('/api/repositories/upload')
      .attach('file', Buffer.from(source), 'app.py');

    expect(uploadRes.status).toBe(201);
    const repoId = uploadRes.body.repository.id;
    const scanStartRes = await request(app).post(`/api/repositories/${repoId}/scan`).send();
    expect(scanStartRes.status).toBe(202);
    const scanId = scanStartRes.body.scanId;

    const finalStatus = await pollScan(app, repoId, scanId);
    expect(finalStatus.status).toBe('COMPLETED');
    expect(finalStatus.stages.security.state).toBe('COMPLETED');
    expect(finalStatus.stages.patch.state).toBe('COMPLETED');
    expect(finalStatus.stages.validation.state).toBe('COMPLETED');
    expect(finalStatus.stages.confidence.state).toBe('COMPLETED');
    expect(finalStatus.stages.runtime.state).toBe('NOT_APPLICABLE');
    expect(finalStatus.stages.securedFile.state).toBe('COMPLETED');

    // Authoritative findings surface on the status endpoint.
    expect(finalStatus.securityFindings).toBeDefined();
    expect(finalStatus.securityFindings.total_vulnerabilities).toBe(2);
    expect(finalStatus.patches).toBeDefined();
    expect(Object.keys(finalStatus.patches).sort()).toEqual(['vuln-cmd-1', 'vuln-xss-1']);
    expect(finalStatus.remediation.rescanned).toBe(true);
    expect(finalStatus.remediation.beforeFindingsCount).toBe(2);
    expect(finalStatus.remediation.afterFindingsCount).toBe(0);
    expect(finalStatus.remediation.riskReductionPct).toBe(100);
    expect(finalStatus.remediation.patchesAppliedCount).toBe(2);

    const downloadRes = await request(app)
      .get(`/api/repositories/${repoId}/scan/${scanId}/download`)
      .buffer(true)
      .parse((res, cb) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => cb(null, Buffer.concat(chunks)));
      });

    expect(downloadRes.status).toBe(200);
    expect(downloadRes.headers['content-disposition']).toContain('app_secured.py');
    const body = downloadRes.body.toString('utf8');
    expect(body).toContain('subprocess.run(["ls", request.args.get("path")], check=False)');
    expect(body).toContain('flask.escape(request.args.get("q"))');
    expect(body).not.toContain('os.system(cmd)');
    expect(body).not.toContain('render_template_string("<p>');
  });

  it('Sandbox unavailable: validation stays truthful and scan still completes', async () => {
    const fakeAi = new StatefulFakeAiEngine();
    fakeAi.beforeFindings = [
      {
        id: 'vuln-sqli-1',
        vulnerability_type: 'SQL Injection',
        severity: 'CRITICAL',
        file: 'query.py',
        line: 3,
        code_snippet: '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
      },
    ];
    fakeAi.beforeVulnerabilities = 1;
    fakeAi.afterFindings = [];

    fakeAi.patches['vuln-sqli-1'] = {
      patch_id: 'patch-sqli-1',
      candidates: [
        {
          candidate_id: 'patch-sqli-1-c0',
          modified_code: '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
          strategy: 'parameterize',
          language: 'python',
        },
      ],
    };
    fakeAi.validation['vuln-sqli-1'] = {
      vulnerability_id: 'vuln-sqli-1',
      candidates: [
        {
          candidate_id: 'patch-sqli-1-c0',
          patch_id: 'patch-sqli-1',
          final_patch: '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
          strategy: 'parameterize',
        },
      ],
      results: [
        {
          candidate_id: 'patch-sqli-1-c0',
          syntax_valid: true,
          semantics_verified: null,
          security_verified: null,
          verdict: 'PASS_UNVERIFIED',
        },
      ],
      sandbox_status: 'NOT_AVAILABLE',
      sandbox_execution: null,
      passed_candidate_id: 'patch-sqli-1-c0',
      passed: true,
    };
    fakeAi.recommendation['vuln-sqli-1'] = {
      recommendation: {
        vulnerability_id: 'vuln-sqli-1',
        patch_id: 'patch-sqli-1',
        ranked_patches: [
          {
            candidate_id: 'patch-sqli-1-c0',
            confidence_score: 85,
            semantic_similarity: 0.87,
            security_delta: 0.9,
            test_delta: 0,
            recommended: true,
          },
        ],
      },
    };

    setOrchestrationServiceForTesting(new OrchestrationService(fakeAi as unknown as AiEngineClient));
    const app = createApp();

    const source = 'import sqlite3\n\ndef lookup(con, user_id):\n    cursor = con.cursor()\n    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n    return cursor.fetchall()\n';
    const uploadRes = await request(app)
      .post('/api/repositories/upload')
      .attach('file', Buffer.from(source), 'query.py');
    expect(uploadRes.status).toBe(201);
    const repoId = uploadRes.body.repository.id;
    const scanStartRes = await request(app).post(`/api/repositories/${repoId}/scan`).send();
    const scanId = scanStartRes.body.scanId;

    const finalStatus = await pollScan(app, repoId, scanId);
    expect(finalStatus.status).toBe('COMPLETED');
    // Validation reports UNVERIFIED honestly (sandbox unavailable) but does not
    // fail the pipeline; the downstream ACE-based eligibility policy applies.
    expect(finalStatus.stages.validation.state).toBe('COMPLETED');
    expect(finalStatus.stages.validation.details).toBeDefined();
    expect(finalStatus.stages.validation.details.unverifiedResults).toBe(1);
    expect(finalStatus.stages.confidence.state).toBe('COMPLETED');
    expect(finalStatus.confidence).toBe(85);
    expect(finalStatus.stages.securedFile.state).toBe('COMPLETED');
    // The CRITICAL finding was remediated and the re-scan is clean, so with
    // ACE >= 80 and all gates passed the artifact is authorized for download.
    expect(finalStatus.securityVerdict).toBe('PASSED');
    expect(finalStatus.artifactAuthorization).toBe('AUTHORIZED');
    expect(finalStatus.downloadEligibility).toMatchObject({
      eligible: true,
      level: 'AUTHORIZED',
      acknowledgementRequired: false,
      aceScore: 85,
    });
    expect(finalStatus.hasOutputFile).toBe(true);

    const downloadRes = await request(app)
      .get(`/api/repositories/${repoId}/scan/${scanId}/download`)
      .buffer();

    expect(downloadRes.status).toBe(200);
    expect(downloadRes.headers['content-disposition']).toContain('attachment');
    expect(downloadRes.body.toString('utf8')).toContain('cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))');
    expect(downloadRes.body.toString('utf8')).not.toContain('cursor.execute("SELECT * FROM users WHERE id = " + user_id)');
  });

  it('Malformed ZIP upload is rejected at ingestion (400)', async () => {
    const fakeAi = new StatefulFakeAiEngine();
    fakeAi.beforeFindings = [];
    fakeAi.beforeVulnerabilities = 0;
    setOrchestrationServiceForTesting(new OrchestrationService(fakeAi as unknown as AiEngineClient));
    const app = createApp();

    const uploadRes = await request(app)
      .post('/api/repositories/upload')
      .attach('file', Buffer.from('NOT_A_REAL_ZIP_HEADER'), 'corrupt.zip');

    expect(uploadRes.status).toBe(400);
    expect(uploadRes.body.error).toContain('Invalid archive');
  });

  it('AI engine outage in non-critical stage (analysis) does not fail the scan', async () => {
    const fakeAi = new StatefulFakeAiEngine();
    fakeAi.beforeFindings = [];
    fakeAi.beforeVulnerabilities = 0;
    fakeAi.failAnalysis = true;
    const originalRequest = fakeAi.request.bind(fakeAi);
    fakeAi.request = async (opts: any) => {
      if ((opts.path ?? '').includes('/analyzer/analyze')) {
        return { status: 500, ok: false, data: { error: { message: 'AI engine down' } } };
      }
      return originalRequest(opts);
    };

    setOrchestrationServiceForTesting(new OrchestrationService(fakeAi as unknown as AiEngineClient));
    const app = createApp();

    const uploadRes = await request(app)
      .post('/api/repositories/upload')
      .attach('file', Buffer.from('def ok():\n    return 42\n'), 'ok.py');
    expect(uploadRes.status).toBe(201);
    const repoId = uploadRes.body.repository.id;
    const scanStartRes = await request(app).post(`/api/repositories/${repoId}/scan`).send();
    expect(scanStartRes.status).toBe(202);
    const scanId = scanStartRes.body.scanId;

    const finalStatus = await pollScan(app, repoId, scanId);
    expect(finalStatus.status).toBe('COMPLETED');
    expect(finalStatus.stages.analysis.state).toBe('FAILED');
    expect(finalStatus.stages.hallucination.state).toBe('COMPLETED');
    expect(finalStatus.stages.security.state).toBe('COMPLETED');
    expect(finalStatus.stages.securedFile.state).toBe('COMPLETED');
    expect(finalStatus.hasOutputFile).toBe(true);
  });
});