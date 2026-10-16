import { pool, checkDatabaseHealth } from '../src/config/db';
import { runMigrations } from '../src/db/migrate';
import { seedDatabase } from '../src/db/seed';
import {
  UserModel,
  RepositoryModel,
  ScanModel,
  VulnerabilityModel,
  HallucinationFindingModel,
  PatchModel,
  ValidationResultModel,
  ConfidenceScoreModel,
  DeveloperFeedbackModel,
  RuntimeEventModel,
} from '../src/models';

describe('Milestone 2: PostgreSQL Database & Domain Models Test Suite', () => {
  let isDbAvailable = false;

  beforeAll(async () => {
    const health = await checkDatabaseHealth();
    isDbAvailable = health.connected;
    if (!isDbAvailable) {
      console.warn('Database not available for integration tests. Run Postgres via Docker Compose or local server.');
    } else {
      await runMigrations();
    }
  });

  afterAll(async () => {
    if (isDbAvailable) {
      await pool.end();
    }
  });

  test('Database Health Check', async () => {
    const health = await checkDatabaseHealth();
    expect(health).toHaveProperty('connected');
  });

  test('Run Migrations & Schema Initialization', async () => {
    if (!isDbAvailable) return;
    const success = await runMigrations();
    expect(success).toBe(true);

    const { rows: tableRows } = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
    `);
    const tables = tableRows.map((r: { table_name: string }) => r.table_name);
    
    expect(tables).toContain('users');
    expect(tables).toContain('repositories');
    expect(tables).toContain('scans');
    expect(tables).toContain('vulnerabilities');
    expect(tables).toContain('hallucination_findings');
    expect(tables).toContain('patches');
    expect(tables).toContain('validation_results');
    expect(tables).toContain('confidence_scores');
    expect(tables).toContain('developer_feedbacks');
    expect(tables).toContain('runtime_events');
    expect(tables).toContain('schema_migrations');
  });

  test('User Model CRUD Operations', async () => {
    if (!isDbAvailable) return;
    const username = `test_dev_${Date.now()}`;
    const email = `test_${Date.now()}@example.com`;

    const user = await UserModel.create({
      username,
      email,
      role: 'DEVELOPER',
      metadata: { department: 'Test QA' },
    });

    expect(user.id).toBeDefined();
    expect(user.username).toBe(username);
    expect(user.email).toBe(email);
    expect(user.role).toBe('DEVELOPER');

    const found = await UserModel.findById(user.id);
    expect(found).not.toBeNull();
    expect(found?.username).toBe(username);

    const foundByEmail = await UserModel.findByEmail(email);
    expect(foundByEmail?.id).toBe(user.id);
  });

  test('Repository Model & Backward Compatibility View', async () => {
    if (!isDbAvailable) return;
    const user = await UserModel.create({
      username: `repo_owner_${Date.now()}`,
      email: `owner_${Date.now()}@example.com`,
    });

    const repo = await RepositoryModel.create({
      owner_id: user.id,
      name: 'test-app-repo',
      url: 'https://github.com/test/test-app-repo.git',
      language: 'TypeScript',
      metadata: { tags: ['express', 'pg'] },
    });

    expect(repo.id).toBeDefined();
    expect(repo.name).toBe('test-app-repo');

    // Test backward compatibility 'projects' view
    const { rows: projectRows } = await pool.query('SELECT * FROM projects WHERE id = $1', [repo.id]);
    expect(projectRows.length).toBe(1);
    expect(projectRows[0].name).toBe('test-app-repo');
    expect(projectRows[0].repository_url).toBe('https://github.com/test/test-app-repo.git');
  });

  test('Scan & Vulnerability & Hallucination Models', async () => {
    if (!isDbAvailable) return;
    const user = await UserModel.create({
      username: `scan_user_${Date.now()}`,
      email: `scan_user_${Date.now()}@example.com`,
    });

    const repo = await RepositoryModel.create({
      owner_id: user.id,
      name: 'scan-test-repo',
      url: 'https://github.com/test/scan-test-repo.git',
    });

    const scan = await ScanModel.create({
      repository_id: repo.id,
      triggered_by: user.id,
      commit_hash: '1234567890abcdef1234567890abcdef12345678',
      branch: 'main',
    });

    expect(scan.status).toBe('PENDING');

    const updatedScan = await ScanModel.updateStatus(scan.id, 'COMPLETED');
    expect(updatedScan?.status).toBe('COMPLETED');
    expect(updatedScan?.completed_at).toBeDefined();

    const vuln = await VulnerabilityModel.create({
      scan_id: scan.id,
      rule_id: 'CWE-89',
      type: 'SQL_INJECTION',
      severity: 'HIGH',
      file_path: 'src/db.ts',
      start_line: 10,
      description: 'Raw SQL concatenation',
    });

    expect(vuln.id).toBeDefined();
    expect(vuln.scan_id).toBe(scan.id);

    const finding = await HallucinationFindingModel.create({
      scan_id: scan.id,
      vulnerability_id: vuln.id,
      category: 'PHANTOM_METHOD',
      symbol_name: 'db.executeRawQueryUnsafe()',
      file_path: 'src/db.ts',
      line_number: 10,
    });

    expect(finding.id).toBeDefined();
    expect(finding.symbol_name).toBe('db.executeRawQueryUnsafe()');
  });

  test('Patch, Validation, Explainable Confidence Score & Developer Feedback Chain', async () => {
    if (!isDbAvailable) return;
    const user = await UserModel.create({
      username: `chain_user_${Date.now()}`,
      email: `chain_user_${Date.now()}@example.com`,
    });

    const repo = await RepositoryModel.create({
      owner_id: user.id,
      name: 'chain-repo',
      url: 'https://github.com/test/chain-repo.git',
    });

    const scan = await ScanModel.create({ repository_id: repo.id });
    const vuln = await VulnerabilityModel.create({
      scan_id: scan.id,
      rule_id: 'CWE-79',
      type: 'XSS',
      severity: 'MEDIUM',
      file_path: 'src/render.ts',
    });

    const patch = await PatchModel.create({
      scan_id: scan.id,
      vulnerability_id: vuln.id,
      diff: '- res.send(input);\n+ res.send(escapeHtml(input));',
      explanation: 'Escape HTML to prevent XSS',
    });

    expect(patch.id).toBeDefined();

    const validation = await ValidationResultModel.create({
      patch_id: patch.id,
      syntax_valid: true,
      type_check_passed: true,
      unit_tests_passed: true,
      sandbox_exit_code: 0,
      execution_time_ms: 1200,
    });

    expect(validation.id).toBeDefined();

    // Verify AI Engine ACE Confidence Score Components (6 features + gates)
    const confidence = await ConfidenceScoreModel.create({
      patch_id: patch.id,
      validation_result_id: validation.id,
      final_score: 96.2,
      static_security_score: 0.95,
      unit_test_success_score: 1.0,
      regression_success_score: 1.0,
      compilation_score: 1.0,
      performance_score: 0.95,
      historical_success_score: 0.90,
      pi_comp: 1.0,
      pi_crit: 1.0,
      weighted_sum: 0.962,
      weights_applied: {
        static_security: 0.25,
        unit_test_success: 0.20,
        regression_success: 0.20,
        compilation_score: 0.10,
        performance: 0.10,
        historical_success: 0.15,
      },
      explanation: 'High confidence patch: All tests pass (1.00), compiles cleanly (1.00), no regressions (1.00), security clean (0.95), performance within range (0.95), supported by historical feedback (0.90). π_comp=1.0, π_crit=1.0.',
      metadata: { ace_version: 'v1.0', algorithm: 'adaptive_confidence_engine' },
    });

    expect(confidence.id).toBeDefined();
    expect(confidence.final_score).toBe(96.2);
    expect(confidence.static_security_score).toBe(0.95);
    expect(confidence.unit_test_success_score).toBe(1.0);
    expect(confidence.regression_success_score).toBe(1.0);
    expect(confidence.compilation_score).toBe(1.0);
    expect(confidence.performance_score).toBe(0.95);
    expect(confidence.historical_success_score).toBe(0.90);
    expect(confidence.pi_comp).toBe(1.0);
    expect(confidence.pi_crit).toBe(1.0);
    expect(confidence.weighted_sum).toBe(0.962);

    // Verify Developer Acceptance Feedback
    const acceptFeedback = await DeveloperFeedbackModel.create({
      patch_id: patch.id,
      user_id: user.id,
      action: 'ACCEPTED',
      reasons: ['CORRECT_FIX', 'HIGH_CONFIDENCE'],
      comments: 'Patch verified by team lead',
    });

    expect(acceptFeedback.id).toBeDefined();
    expect(acceptFeedback.action).toBe('ACCEPTED');

    // Verify Developer Rejection Feedback
    const rejectFeedback = await DeveloperFeedbackModel.create({
      patch_id: patch.id,
      user_id: user.id,
      action: 'REJECTED',
      reasons: ['CODE_STYLE', 'PREFER_ALTERNATIVE_LIB'],
      comments: 'Use DOMPurify instead of custom escapeHtml',
    });

    expect(rejectFeedback.action).toBe('REJECTED');
    expect(rejectFeedback.reasons).toContain('CODE_STYLE');
  });

  test('Runtime Event Tracking & Querying', async () => {
    if (!isDbAvailable) return;
    const repo = await RepositoryModel.create({
      name: 'runtime-event-repo',
      url: 'https://github.com/test/runtime-event-repo.git',
    });

    const event = await RuntimeEventModel.create({
      repository_id: repo.id,
      event_type: 'EXECUTION_EXCEPTION',
      severity: 'CRITICAL',
      stack_trace: 'ReferenceError: phantomSymbol is not defined at index.js:12:4',
      payload: { process_id: 4892, context: 'sandbox_eval' },
    });

    expect(event.id).toBeDefined();
    expect(event.event_type).toBe('EXECUTION_EXCEPTION');

    const events = await RuntimeEventModel.findByRepositoryId(repo.id);
    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events[0].severity).toBe('CRITICAL');
  });

  test('Seed Script Execution Test', async () => {
    if (!isDbAvailable) return;
    const seeded = await seedDatabase();
    expect(seeded).toBe(true);

    const repos = await RepositoryModel.list(10);
    expect(repos.length).toBeGreaterThan(0);
  });
});
