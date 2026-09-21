import { runMigrations } from './migrate';
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
} from '../models';

export async function seedDatabase(): Promise<boolean> {
  console.log('[Seed] Starting database seeding...');

  // Ensure schema migrations are up to date
  const migrated = await runMigrations();
  if (!migrated) {
    console.error('[Seed] Cannot seed database: migrations failed or database unreachable.');
    return false;
  }

  try {
    // 1. Create Seed Users (idempotent: reuse existing seed users if present)
    console.log('[Seed] Creating users...');
    let devUser = await UserModel.findByUsername('dev_alex');
    if (!devUser) {
      devUser = await UserModel.create({
        username: 'dev_alex',
        email: 'alex@hallucishield.ai',
        role: 'DEVELOPER',
        metadata: { department: 'Security Engineering', preferred_llm: 'deepseek-coder:6.7b' },
      });
    }

    let auditorUser = await UserModel.findByUsername('auditor_sarah');
    if (!auditorUser) {
      auditorUser = await UserModel.create({
        username: 'auditor_sarah',
        email: 'sarah@hallucishield.ai',
        role: 'AUDITOR',
        metadata: { department: 'Compliance & Audit' },
      });
    }

    console.log(`[Seed] Users ready: ${devUser.id}, ${auditorUser.id}`);

    // 2. Create Seed Repository
    console.log('[Seed] Creating repository...');
    const repo = await RepositoryModel.create({
      owner_id: devUser.id,
      name: 'halluci-express-demo',
      url: 'https://github.com/hallucishield/halluci-express-demo.git',
      default_branch: 'main',
      language: 'TypeScript',
      is_active: true,
      metadata: { framework: 'Express', target_node_version: '20.x' },
    });
    console.log(`[Seed] Created repository: ${repo.id}`);

    // 3. Create Seed Scan
    console.log('[Seed] Creating scan...');
    const scan = await ScanModel.create({
      repository_id: repo.id,
      triggered_by: devUser.id,
      status: 'COMPLETED',
      commit_hash: 'a1b2c3d4e5f67890123456789abcdef012345678',
      branch: 'main',
      workspace_path: '/tmp/sandboxes/halluci-express-demo',
      file_count: 42,
      metadata: { trigger_source: 'GITHUB_WEBHOOK', analyzer_version: '1.2.0' },
    });
    await ScanModel.updateStatus(scan.id, 'COMPLETED');
    console.log(`[Seed] Created scan: ${scan.id}`);

    // 4. Create Seed Vulnerabilities
    console.log('[Seed] Creating vulnerabilities...');
    const vuln1 = await VulnerabilityModel.create({
      scan_id: scan.id,
      rule_id: 'js.sql-injection.pg-query',
      type: 'SQL_INJECTION',
      severity: 'CRITICAL',
      file_path: 'src/controllers/userController.ts',
      start_line: 45,
      end_line: 48,
      description: 'Unsanitized user input formatted directly into raw PostgreSQL query string',
      cwe: 'CWE-89',
      raw_details: { semgrep_rule: 'javascript.express.security.audit.sqli', match: 'pool.query(`SELECT * FROM users WHERE id = ${req.params.id}`)' },
    });

    const vuln2 = await VulnerabilityModel.create({
      scan_id: scan.id,
      rule_id: 'js.insecure-jwt-verify',
      type: 'INSECURE_AUTHENTICATION',
      severity: 'HIGH',
      file_path: 'src/middleware/auth.ts',
      start_line: 22,
      end_line: 25,
      description: 'JWT verification bypass due to hallucinated algorithm parameter',
      cwe: 'CWE-287',
      raw_details: { rule_name: 'jwt-none-algorithm-allowed' },
    });
    console.log(`[Seed] Created vulnerabilities: ${vuln1.id}, ${vuln2.id}`);

    // 5. Create Seed Hallucination Finding
    console.log('[Seed] Creating hallucination finding...');
    const hallucination = await HallucinationFindingModel.create({
      scan_id: scan.id,
      vulnerability_id: vuln2.id,
      category: 'HALLUCINATED_DEPENDENCY',
      symbol_name: 'express-jwt-auto-auth',
      file_path: 'package.json',
      line_number: 18,
      snippet: '"express-jwt-auto-auth": "^2.1.0"',
      raw_details: {
        registry_check: 'NPM_REGISTRY_404',
        npm_exists: false,
        risk_level: 'HIGH_SLUGCASHING_RISK',
      },
    });
    console.log(`[Seed] Created hallucination finding: ${hallucination.id}`);

    // 6. Create Seed Patch
    console.log('[Seed] Creating patch...');
    const patch = await PatchModel.create({
      scan_id: scan.id,
      vulnerability_id: vuln1.id,
      hallucination_finding_id: hallucination.id,
      diff: `--- a/src/controllers/userController.ts
+++ b/src/controllers/userController.ts
@@ -45,3 +45,3 @@
-  const result = await pool.query(\`SELECT * FROM users WHERE id = '\${req.params.id}'\`);
+  const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
   return res.json(result.rows[0]);`,
      explanation: 'Replaced inline string interpolation with parameterized SQL query placeholder ($1)',
      status: 'APPROVED',
      patch_metadata: { model: 'deepseek-coder:6.7b', tokens_used: 480, generation_latency_ms: 1240 },
    });
    console.log(`[Seed] Created patch: ${patch.id}`);

    // 7. Create Seed Validation Result
    console.log('[Seed] Creating validation result...');
    const validation = await ValidationResultModel.create({
      patch_id: patch.id,
      syntax_valid: true,
      type_check_passed: true,
      unit_tests_passed: true,
      sandbox_exit_code: 0,
      execution_time_ms: 3450,
      stdout: 'PASS src/controllers/userController.test.ts (2 passed)',
      stderr: '',
      details: {
        total_tests: 2,
        passed_tests: 2,
        failed_tests: 0,
        coverage_percentage: 95.4,
      },
    });
    console.log(`[Seed] Created validation result: ${validation.id}`);

    // 8. Create Seed Confidence Score (Explainable components breakdown)
    console.log('[Seed] Creating explainable confidence score...');
    const confidence = await ConfidenceScoreModel.create({
      patch_id: patch.id,
      validation_result_id: validation.id,
      static_analysis_score: 0.9500,
      hallucination_score: 0.9000,
      sandbox_validation_score: 1.0000,
      runtime_event_score: 0.8500,
      historical_feedback_score: 0.9000,
      weights_applied: {
        static_analysis: 0.20,
        hallucination: 0.30,
        sandbox_validation: 0.30,
        runtime_event: 0.10,
        historical_feedback: 0.10,
      },
      explanation: 'High confidence patch: Passes all sandbox tests (1.00), verified real npm dependency (0.90), resolves SQL injection (0.95), supported by positive historical feedback (0.90).',
      metadata: { ace_version: 'v2.1' },
    });
    console.log(`[Seed] Created confidence score: ${confidence.id} with final score: ${confidence.final_score}`);

    // 9. Create Seed Developer Feedback (Acceptance / Rejection recording)
    console.log('[Seed] Creating developer feedback...');
    const feedbackAccepted = await DeveloperFeedbackModel.create({
      patch_id: patch.id,
      user_id: devUser.id,
      action: 'ACCEPTED',
      reasons: ['CORRECT_PARAMETERIZATION', 'SANDBOX_PASSED'],
      comments: 'Patch cleanly parameterizes the raw SQL query and removes vulnerability without side-effects.',
      metadata: { review_duration_seconds: 45 },
    });
    console.log(`[Seed] Created developer feedback: ${feedbackAccepted.id}`);

    // 10. Create Seed Runtime Event
    console.log('[Seed] Creating runtime event...');
    const runtimeEvent = await RuntimeEventModel.create({
      repository_id: repo.id,
      scan_id: scan.id,
      patch_id: patch.id,
      event_type: 'PACKAGE_VERIFICATION_ALERT',
      severity: 'HIGH',
      stack_trace: 'Error: Cannot find module "express-jwt-auto-auth"\n    at Module._resolveFilename (node:internal/modules/cjs/loader:1077:15)',
      payload: { missing_package: 'express-jwt-auto-auth', registry: 'https://registry.npmjs.org/' },
    });
    console.log(`[Seed] Created runtime event: ${runtimeEvent.id}`);

    console.log('[Seed] Database seeding completed successfully.');
    return true;
  } catch (err) {
    console.error('[Seed] Error seeding database:', err);
    throw err;
  }
}

if (require.main === module) {
  seedDatabase()
    .then(() => process.exit(0))
    .catch(() => process.exit(1));
}
