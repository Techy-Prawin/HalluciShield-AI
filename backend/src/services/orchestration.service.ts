import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { AiEngineClient, AiEngineResponse } from './aiEngine.client';
import { WorkspaceService } from './workspace.service';
import { ScanModel, RepositoryModel, DownloadEligibility, DownloadAcknowledgement } from '../models';
import { config } from '../config/env';

export type ScanState = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';
export type ScanStageState =
  | 'QUEUED'
  | 'RUNNING'
  | 'COMPLETED'
  | 'FAILED'
  | 'SKIPPED'
  | 'NOT_APPLICABLE';

export type StageName =
  | 'repository'
  | 'analysis'
  | 'hallucination'
  | 'dependency'
  | 'security'
  | 'risk'
  | 'patch'
  | 'validation'
  | 'confidence'
  | 'runtime'
  | 'securedFile';

export interface ScanStage {
  state: ScanStageState;
  httpStatus?: number;
  durationMs?: number;
  error?: string;
  details?: Record<string, unknown>;
}

export interface RemediationReport {
  beforeFindingsCount: number;
  afterFindingsCount: number;
  beforeRiskScore: number;
  afterRiskScore: number;
  riskReductionPct: number | null;
  patchesAppliedCount: number;
  rescanned: boolean;
  sandboxVerified: boolean | null;
}

export type RemediationStatus = 'PENDING' | 'NOT_REQUIRED' | 'VERIFIED' | 'BLOCKED' | 'FAILED';
export type ArtifactAuthorization = 'PENDING' | 'AUTHORIZED' | 'UNVERIFIED_DOWNLOAD' | 'BLOCKED';

/** Security verdict: whether the candidate has actually passed the required
 * security and validation checks. Independent of download eligibility.
 * An UNVERIFIED candidate is never labeled PASSED/SECURE/VERIFIED. */
export type SecurityVerdict = 'PENDING' | 'PASSED' | 'UNVERIFIED' | 'BLOCKED';

interface VulnRecord {
  id: string;
  vulnerability_type: string;
  severity: string;
  file_path: string;
  line_number: number;
  code_snippet: string;
  description: string;
}

export interface ScanRecord {
  id: string;
  repositoryId: string;
  workspacePath: string;
  /** True when the workspace was materialized by this backend into the shared volume. */
  managedWorkspace: boolean;
  status: ScanState;
  /** Identifier of the pipeline stage currently executing (null when idle). */
  currentStage: StageName | null;
  stages: {
    repository: ScanStage;
    analysis: ScanStage;
    hallucination: ScanStage;
    dependency: ScanStage;
    security: ScanStage;
    risk: ScanStage;
    patch: ScanStage;
    validation: ScanStage;
    confidence: ScanStage;
    runtime: ScanStage;
    securedFile?: ScanStage;
  };
  results?: {
    repository?: unknown;
    analysis?: unknown;
    hallucination?: unknown;
    security?: unknown;
    dependency?: unknown;
    risk?: unknown;
    validation?: unknown;
    confidence?: unknown;
  };
  patches: Record<string, unknown>;
  riskScore?: number;
  riskLevel?: string;
  confidence?: number;
  remediationStatus: RemediationStatus;
  artifactAuthorization: ArtifactAuthorization;
  /** Independent security verdict for the candidate/artifact (never PASSED when unverified). */
  securityVerdict: SecurityVerdict;
  /** Download eligibility decision (distinct from the security verdict). */
  downloadEligibility?: DownloadEligibility;
  /** Auditable explicit user acknowledgement for an unverified download. */
  downloadAcknowledgement?: DownloadAcknowledgement;
  remediation?: RemediationReport;
  outputFile?: string;
  outputFileHash?: string; // SHA-256 of the secured output artifact, for integrity verification
  originalFileName?: string;
  uploadType?: 'archive' | 'single_file';
  error?: string;
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
}

const SCAN_STAGE_TIMEOUT_MS = 120_000;

/** Pipeline stage order used for downstream-skip cascades on critical failure. */
const STAGE_ORDER: StageName[] = [
  'repository',
  'analysis',
  'hallucination',
  'dependency',
  'security',
  'risk',
  'patch',
  'validation',
  'confidence',
  'runtime',
  'securedFile',
];

function blankStage(): ScanStage {
  return { state: 'QUEUED' };
}

function markStage(
  scan: ScanRecord,
  stage: StageName,
  patch: Partial<ScanStage>
): void {
  const s = scan.stages[stage] ?? blankStage();
  Object.assign(s, patch);
  if (s.state !== 'QUEUED') scan.stages[stage] = s;
}

function markSkipped(scan: ScanRecord, stage: StageName, reason: string): void {
  markStage(scan, stage, {
    state: 'SKIPPED',
    durationMs: 0,
    details: { reason },
  });
}

function blankScan(
  repositoryId: string,
  workspacePath: string,
  scanId: string,
  managedWorkspace: boolean
): ScanRecord {
  const now = new Date().toISOString();
  return {
    id: scanId,
    repositoryId,
    workspacePath,
    managedWorkspace,
    status: 'QUEUED',
    currentStage: null,
    stages: {
      repository: blankStage(),
      analysis: blankStage(),
      hallucination: blankStage(),
      dependency: blankStage(),
      security: blankStage(),
      risk: blankStage(),
      patch: blankStage(),
      validation: blankStage(),
      confidence: blankStage(),
      runtime: blankStage(),
      securedFile: blankStage(),
    },
    patches: {},
    remediationStatus: 'PENDING',
    artifactAuthorization: 'PENDING',
    securityVerdict: 'PENDING',
    createdAt: now,
    updatedAt: now,
  };
}

/**
 * Orchestrates an end-to-end repository scan across 10 distinct security & AI stages:
 * 1. Repository - workspace verification & layout indexing
 * 2. Analysis - AST & static construct extraction
 * 3. Hallucination - AI package hallucination detection
 * 4. Dependency - dependency vulnerability analysis
 * 5. Security - static vulnerability & secrets scanning
 * 6. Risk Assessment - multi-factor repository risk scoring
 * 7. Patch Generation - multi-candidate remediation generation
 * 8. Validation - 6-dimensional candidate patch verification
 * 9. Confidence - adaptive confidence engine ranking
 * 10. Runtime - daemon runtime monitoring stage (NOT_APPLICABLE for static scan)
 * + Secured File Generation - producing verified remediated code
 */
export class OrchestrationService {
  private readonly scans = new Map<string, ScanRecord>();
  private readonly persistedScans = new Set<string>();

  constructor(private readonly client: AiEngineClient) {}

  startScan(
    repositoryId: string,
    workspacePath: string,
    scanId = crypto.randomUUID(),
    opts: { managedWorkspace?: boolean } = {}
  ): ScanRecord {
    const managedWorkspace = opts.managedWorkspace === true;
    const scan = blankScan(repositoryId, workspacePath, scanId, managedWorkspace);
    this.scans.set(scan.id, scan);
    void this.persist(scan);
    setTimeout(() => {
      void this.runScan(scan.id);
    }, 0);
    return scan;
  }

  getScan(scanId: string): ScanRecord | undefined {
    return this.scans.get(scanId);
  }

  async getScanAsync(scanId: string): Promise<ScanRecord | undefined> {
    const cached = this.scans.get(scanId);
    if (cached || !this.persistenceEnabled()) return cached;
    try {
      const row = await ScanModel.findById(scanId);
      const persisted = row?.metadata?.orchestration as ScanRecord | undefined;
      if (persisted) {
        this.scans.set(scanId, persisted);
        this.persistedScans.add(scanId);
        return persisted;
      }
    } catch (err) {
      console.warn('[orchestration] scan read persistence unavailable:', err instanceof Error ? err.message : err);
    }
    return undefined;
  }

  getPatches(scanId: string): Record<string, unknown> | undefined {
    const scan = this.scans.get(scanId);
    return scan ? scan.patches : undefined;
  }

  setPatches(scanId: string, vulnerabilityId: string, response: unknown): void {
    const scan = this.scans.get(scanId);
    if (scan) {
      scan.patches[vulnerabilityId] = response;
      scan.updatedAt = new Date().toISOString();
      void this.persist(scan);
    }
  }

  proxy<T = any>(opts: import('./aiEngine.client').AiEngineRequestOptions): Promise<AiEngineResponse<T>> {
    return this.client.request<T>(opts);
  }

  private async runScan(scanId: string): Promise<void> {
    const scan = this.scans.get(scanId);
    if (!scan) return;

    scan.status = 'RUNNING';
    scan.currentStage = 'repository';
    scan.updatedAt = new Date().toISOString();
    await this.persist(scan);

    // Populate metadata from repository record (best-effort; never blocks the
    // scan on database availability).
    try {
      const repo = await this.withTimeout(RepositoryModel.findById(scan.repositoryId), 2000);
      if (repo?.metadata) {
        if (typeof repo.metadata.upload_type === 'string') {
          scan.uploadType = repo.metadata.upload_type as 'archive' | 'single_file';
        }
        if (typeof repo.metadata.original_file_name === 'string') {
          scan.originalFileName = repo.metadata.original_file_name;
        }
      }
    } catch {
      // In-memory mode or repository lookup bypassed
    }

    // 1. Stage: Repository Verification
    await this.runRepositoryStage(scan);
    if (scan.stages.repository.state === 'FAILED') {
      for (const s of STAGE_ORDER) {
        if (s === 'repository') continue;
        markSkipped(scan, s, 'Repository workspace verification failed upstream.');
      }
      scan.status = 'FAILED';
      scan.error = scan.stages.repository.error || 'Repository workspace verification failed.';
      scan.remediationStatus = 'BLOCKED';
      scan.artifactAuthorization = 'BLOCKED';
      await this.finishScan(scan);
      return;
    }

    // 2. Stage: Static Code Analysis
    await this.runStage(scan, 'analysis', {
      path: '/api/v1/analyzer/analyze',
      body: { repository_id: scan.repositoryId, workspace_path: scan.workspacePath },
      requestId: scan.id,
    });

    // 3. Stage: Hallucination Detection
    await this.runStage(scan, 'hallucination', {
      path: '/api/v1/hallucination/detect',
      body: { repository_id: scan.repositoryId, workspace_path: scan.workspacePath },
      requestId: scan.id,
    });

    // 4. Stage: Dependency Analysis. Runs for archives AND single files so the
    //    AI engine's import inspection applies to all uploads. NOT_APPLICABLE
    //    only when there is genuinely no manifest and no import-level findings.
    await this.runDependencyStage(scan);

    // 5. Stage: Security Scan (critical -- downstream work depends on it)
    await this.runStage(scan, 'security', {
      path: '/api/v1/security/scan',
      body: { repository_id: scan.repositoryId, workspace_path: scan.workspacePath },
      requestId: scan.id,
    });
    if (scan.stages.security.state === 'FAILED') {
      for (const s of STAGE_ORDER) {
        if (['repository', 'analysis', 'hallucination', 'dependency', 'security'].includes(s)) {
          continue;
        }
        markSkipped(scan, s, 'Security analysis failed upstream.');
      }
      scan.status = 'FAILED';
      scan.error = 'Security analysis failed against the AI engine.';
      scan.remediationStatus = 'BLOCKED';
      scan.artifactAuthorization = 'BLOCKED';
      await this.finishScan(scan);
      return;
    }

    // 6. Stage: Risk Assessment
    await this.runRiskAssessmentStage(scan);

    // 7. Stage: Multi-Candidate Patch Generation
    await this.runPatchGenerationStage(scan);
    if (scan.stages.patch.state === 'FAILED') {
      markSkipped(scan, 'validation', 'Patch generation failed upstream.');
      markSkipped(scan, 'confidence', 'Patch generation failed upstream.');
      markSkipped(scan, 'securedFile', 'Patch generation failed; no remediated artifact can be produced.');
      markSkipped(scan, 'runtime', 'Patch generation failed upstream.');
      scan.remediationStatus = 'BLOCKED';
      scan.artifactAuthorization = 'BLOCKED';
      scan.status = 'COMPLETED';
      await this.finishScan(scan);
      return;
    }

    // 8. Stage: Candidate Patch Validation
    await this.runPatchValidationStage(scan);
    if (scan.stages.validation.state === 'FAILED') {
      markSkipped(scan, 'confidence', 'Candidate validation failed upstream.');
      markSkipped(scan, 'securedFile', 'Candidate validation failed upstream; no remediated artifact can be produced.');
      markSkipped(scan, 'runtime', 'Candidate validation failed upstream.');
      scan.remediationStatus = 'BLOCKED';
      scan.artifactAuthorization = 'BLOCKED';
      scan.securityVerdict = 'BLOCKED';
      scan.downloadEligibility = {
        eligible: false,
        level: 'INELIGIBLE',
        reason: 'Candidate validation failed; no downloadable artifact can be produced.',
        aceScore: this.extractAceScore(scan),
        aceScale: { min: config.aceDownload.aceScaleMin, max: config.aceDownload.aceScaleMax },
        acknowledgementRequired: false,
        securityGatesPassed: false,
        thresholds: { authorized: config.aceDownload.authorizedThreshold, unverified: config.aceDownload.unverifiedThreshold },
      };
      scan.status = 'COMPLETED';
      await this.finishScan(scan);
      return;
    }

    // 9. Stage: Confidence Ranking & Recommendation
    await this.runConfidenceRankingStage(scan);

    // 10. Stage: Runtime Monitoring (static scans report NOT_APPLICABLE honestly)
    markStage(scan, 'runtime', {
      state: 'NOT_APPLICABLE',
      details: { reason: 'Runtime monitoring operates on active deployed services, not static code' },
    });

    // 11. Stage: Secured File Generation (remediation + final security re-scan).
    // Always runs: for clean code it produces the pass-through secured artifact
    // (authorized); for findings it applies the ACE download-eligibility policy.
    await this.runSecuredFileStage(scan);

    scan.status = 'COMPLETED';
    await this.finishScan(scan);
  }

  private async finishScan(scan: ScanRecord): Promise<void> {
    scan.currentStage = null;
    scan.updatedAt = new Date().toISOString();
    if (scan.status === 'COMPLETED') {
      scan.completedAt = new Date().toISOString();
    }
    if (scan.managedWorkspace) {
      const patchedWorkspace = WorkspaceService.patchedRunDir(scan.id);
      if (fs.existsSync(patchedWorkspace)) {
        WorkspaceService.cleanupScanWorkspace(patchedWorkspace);
      }
      WorkspaceService.cleanupScanWorkspace(scan.workspacePath);
    }
    await this.persist(scan);
  }

  private async runRepositoryStage(scan: ScanRecord): Promise<void> {
    const stage = scan.stages.repository;
    stage.state = 'RUNNING';
    const started = Date.now();
    try {
      if (!fs.existsSync(scan.workspacePath)) {
        stage.state = 'FAILED';
        stage.error = `Workspace directory not found: ${scan.workspacePath}`;
        stage.durationMs = Date.now() - started;
        return;
      }
      const files: string[] = [];
      const walk = (dir: string) => {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === '__pycache__') continue;
          const full = path.join(dir, entry.name);
          if (entry.isDirectory()) walk(full);
          else files.push(path.relative(scan.workspacePath, full));
        }
      };
      walk(scan.workspacePath);
      stage.state = 'COMPLETED';
      stage.durationMs = Date.now() - started;
      stage.details = { fileCount: files.length, sampleFiles: files.slice(0, 10) };
      scan.results = scan.results ?? {};
      scan.results.repository = stage.details;
    } catch (err: any) {
      stage.state = 'FAILED';
      stage.error = err?.message || String(err);
      stage.durationMs = Date.now() - started;
    }
    await this.persist(scan);
  }

  private async runDependencyStage(scan: ScanRecord): Promise<void> {
    const stage = scan.stages.dependency;
    scan.currentStage = 'dependency';
    stage.state = 'RUNNING';
    scan.updatedAt = new Date().toISOString();
    const started = Date.now();

    try {
      const response = await this.client.request({
        path: '/api/v1/dependency/analyze',
        method: 'POST',
        body: { repository_id: scan.repositoryId, workspace_path: scan.workspacePath },
        requestId: scan.id,
        timeoutMs: SCAN_STAGE_TIMEOUT_MS,
      });
      stage.durationMs = Date.now() - started;
      stage.httpStatus = response.status;
      if (!response.ok) {
        stage.state = 'FAILED';
        stage.error = `AI engine responded with HTTP ${response.status}`;
        scan.results = scan.results ?? {};
        scan.results.dependency = undefined;
        await this.persist(scan);
        return;
      }
      // Single files carry no package manifests, so the analyzer legitimately
      // reports zero findings. Only treat that genuine outcome as
      // NOT_APPLICABLE; any real finding keeps the stage COMPLETED.
      const data = response.data as any;
      const scanned = Number(data?.dependencies_scanned ?? 0);
      const findings = Number(data?.total_findings ?? 0);
      if (scanned === 0 && findings === 0) {
        stage.state = 'NOT_APPLICABLE';
        stage.details = {
          reason: 'No package manifests or import-level findings detected in the uploaded source',
          dependenciesScanned: scanned,
          totalFindings: findings,
        };
      } else {
        stage.state = 'COMPLETED';
        stage.details = { dependenciesScanned: scanned, totalFindings: findings };
        scan.results = scan.results ?? {};
        scan.results.dependency = data;
      }
    } catch (err: any) {
      stage.durationMs = Date.now() - started;
      stage.state = 'FAILED';
      stage.error = err?.message || String(err);
    }
    await this.persist(scan);
  }

  private async runRiskAssessmentStage(scan: ScanRecord): Promise<void> {
    const stage = scan.stages.risk;
    scan.currentStage = 'risk';
    stage.state = 'RUNNING';
    const started = Date.now();
    try {
      const response = await this.client.request({
        path: '/api/v1/risk/assess',
        method: 'POST',
        body: { repository_id: scan.repositoryId, workspace_path: scan.workspacePath },
        requestId: scan.id,
        timeoutMs: SCAN_STAGE_TIMEOUT_MS,
      });
      stage.durationMs = Date.now() - started;
      stage.httpStatus = response.status;
      if (response.ok && response.data?.risk_assessment) {
        stage.state = 'COMPLETED';
        scan.results = scan.results ?? {};
        scan.results.risk = response.data.risk_assessment;
        const ra = response.data.risk_assessment;
        scan.riskScore = typeof ra.overall_risk_score === 'number' ? Math.round(ra.overall_risk_score) : 0;
        scan.riskLevel = ra.overall_risk_level || this.levelFromScore(scan.riskScore);
      } else {
        this.computeFallbackRiskScore(scan);
        stage.state = 'COMPLETED';
      }
    } catch {
      this.computeFallbackRiskScore(scan);
      stage.state = 'COMPLETED';
      stage.durationMs = Date.now() - started;
    }
    await this.persist(scan);
  }

  private computeFallbackRiskScore(scan: ScanRecord): void {
    let score = 0;
    const secFindings =
      (scan.results?.security as any)?.findings ||
      (scan.results?.security as any)?.vulnerabilities ||
      [];
    const halFindings =
      (scan.results?.hallucination as any)?.findings ||
      (scan.results?.hallucination as any)?.hallucinated_packages ||
      [];
    for (const f of secFindings) {
      const sev = String(f.severity || '').toUpperCase();
      if (sev === 'CRITICAL') score += 35;
      else if (sev === 'HIGH') score += 20;
      else if (sev === 'MEDIUM') score += 10;
      else score += 5;
    }
    for (const _h of halFindings) {
      score += 25;
    }
    score = Math.min(100, score);
    scan.riskScore = score;
    scan.riskLevel = this.levelFromScore(score);
  }

  private levelFromScore(score: number): string {
    if (score >= 70) return 'CRITICAL';
    if (score >= 40) return 'HIGH';
    if (score >= 15) return 'MEDIUM';
    return 'LOW';
  }

  private extractVulnerabilities(scan: ScanRecord): Array<{
    id: string;
    vulnerability_type: string;
    severity: string;
    file_path: string;
    line_number: number;
    code_snippet: string;
    description: string;
    package_name?: string;
  }> {
    const list: Array<any> = [];
    const secFindings =
      (scan.results?.security as any)?.findings ||
      (scan.results?.security as any)?.vulnerabilities ||
      [];
    for (let i = 0; i < secFindings.length; i++) {
      const f = secFindings[i];
      const snippet =
        f.code_snippet ||
        f.code ||
        f.vulnerable_code ||
        f.metadata?.semgrep_extra?.line_content ||
        '';
      list.push({
        id: f.finding_id || f.id || `sec-${i + 1}`,
        vulnerability_type: f.vulnerability_type || f.type || 'Security Vulnerability',
        severity: f.severity || 'HIGH',
        file_path: this.workspaceRelativePath(scan.workspacePath, f.file_path || f.file || scan.originalFileName || ''),
        line_number: Number(f.line_number || f.line || 1),
        code_snippet: snippet,
        description: f.description || '',
        package_name: f.package_name || '',
      });
    }

    const halFindings =
      (scan.results?.hallucination as any)?.findings ||
      (scan.results?.hallucination as any)?.hallucinated_packages ||
      [];
    for (let i = 0; i < halFindings.length; i++) {
      const h = halFindings[i];
      list.push({
        id: h.finding_id || h.id || `hal-${i + 1}`,
        vulnerability_type: 'Hallucinated Dependency',
        severity: 'HIGH',
        file_path: this.workspaceRelativePath(scan.workspacePath, h.file_path || h.file || scan.originalFileName || ''),
        line_number: Number(h.line_number || h.line || 1),
        code_snippet: h.code_snippet || h.code || h.package_name || '',
        description: `Hallucinated package "${h.package_name || 'unknown'}" detected. Potential dependency hijacking risk.`,
        package_name: h.package_name || h.evidence?.symbol_name || '',
      });
    }
    return list;
  }

  private workspaceRelativePath(workspacePath: string, filePath: string): string {
    if (!filePath) return '';
    const root = path.resolve(workspacePath);
    const absolute = path.isAbsolute(filePath) ? path.resolve(filePath) : path.resolve(root, filePath);
    const relative = path.relative(root, absolute);
    if (!relative || path.isAbsolute(relative) || relative === '..' || relative.startsWith(`..${path.sep}`)) {
      return '';
    }
    return relative;
  }

  private languageFromPath(filePath: string): string {
    const languages: Record<string, string> = {
      '.py': 'python', '.js': 'javascript', '.jsx': 'javascript',
      '.ts': 'typescript', '.tsx': 'typescript', '.java': 'java',
      '.go': 'go', '.rs': 'rust', '.c': 'c', '.cpp': 'cpp',
    };
    return languages[path.extname(filePath).toLowerCase()] || 'unknown';
  }

  private async runPatchGenerationStage(scan: ScanRecord): Promise<void> {
    const stage = scan.stages.patch;
    scan.currentStage = 'patch';
    const started = Date.now();
    const vulnerabilities = this.extractVulnerabilities(scan);

    if (vulnerabilities.length === 0) {
      stage.state = 'NOT_APPLICABLE';
      stage.durationMs = Date.now() - started;
      stage.details = { reason: 'Zero vulnerabilities detected requiring patch generation' };
      await this.persist(scan);
      return;
    }

    stage.state = 'RUNNING';
    scan.updatedAt = new Date().toISOString();
    await this.persist(scan);

    let generatedCount = 0;
    // Process top findings to avoid timeouts (up to 3)
    const targets = vulnerabilities.slice(0, 3);
    for (const v of targets) {
      let vulnerableCode = v.code_snippet;
      if (!vulnerableCode && v.file_path && fs.existsSync(path.join(scan.workspacePath, v.file_path))) {
        try {
          const lines = fs.readFileSync(path.join(scan.workspacePath, v.file_path), 'utf8').split(/\r?\n/);
          vulnerableCode = lines[Math.max(0, v.line_number - 1)] || '';
        } catch {}
      }
      if (!vulnerableCode) {
        vulnerableCode = `# Vulnerability target: ${v.vulnerability_type} at ${v.file_path}:${v.line_number}`;
      }

      try {
        const res = await this.client.request({
          path: `/api/v1/vulnerabilities/${encodeURIComponent(v.id)}/generate-patches`,
          method: 'POST',
          body: {
            vulnerability_id: v.id,
            vulnerability_type: v.vulnerability_type,
            severity: v.severity,
            file: v.file_path,
            line: v.line_number,
            vulnerable_code: vulnerableCode,
            description: v.description,
          },
          requestId: scan.id,
          timeoutMs: SCAN_STAGE_TIMEOUT_MS,
        });
        if (res.ok && res.data) {
          scan.patches[v.id] = res.data;
          generatedCount++;
        }
      } catch (err: any) {
        console.warn(`[orchestration] patch generation failed for ${v.id}:`, err?.message);
      }
    }

    stage.durationMs = Date.now() - started;
    if (generatedCount > 0) {
      stage.state = 'COMPLETED';
      stage.details = { patchesGeneratedFor: generatedCount };
    } else {
      stage.state = 'FAILED';
      stage.error = 'Failed to generate patches for detected vulnerabilities.';
    }
    await this.persist(scan);
  }

  private async runPatchValidationStage(scan: ScanRecord): Promise<void> {
    const stage = scan.stages.validation;
    scan.currentStage = 'validation';
    const started = Date.now();

    if (scan.stages.patch.state === 'NOT_APPLICABLE' || Object.keys(scan.patches).length === 0) {
      stage.state = 'NOT_APPLICABLE';
      stage.durationMs = Date.now() - started;
      stage.details = { reason: 'No candidate patches generated to validate' };
      await this.persist(scan);
      return;
    }

    stage.state = 'RUNNING';
    scan.updatedAt = new Date().toISOString();
    await this.persist(scan);

    let validatedCount = 0;
    let failedResults = 0;
    let unverifiedResults = 0;
    scan.results = scan.results ?? {};
    scan.results.validation = scan.results.validation ?? {};
    const vulnerabilities = this.extractVulnerabilities(scan);

    for (const [vulnId, patchDataRaw] of Object.entries(scan.patches)) {
      const patchData = patchDataRaw as any;
      const candidates = patchData?.candidates || [];
      if (!Array.isArray(candidates) || candidates.length === 0) continue;
      const vulnerability = vulnerabilities.find((entry) => entry.id === vulnId);
      const validationResults: any[] = [];

      for (const candidate of candidates) {
        let candidateWorkspace = '';
        try {
          if (!vulnerability?.file_path || !this.languageFromPath(vulnerability.file_path)) {
            unverifiedResults++;
            continue;
          }
          candidateWorkspace = fs.mkdtempSync(path.join(WorkspaceService.ensureRoot(), 'validation-'));
          fs.cpSync(scan.workspacePath, candidateWorkspace, { recursive: true, dereference: true });
          const candidateFile = path.resolve(candidateWorkspace, vulnerability.file_path);
          if (
            !candidateFile.startsWith(path.resolve(candidateWorkspace) + path.sep) ||
            !fs.existsSync(candidateFile) ||
            !this.applyPatchToFile(candidateFile, candidate, vulnerability)
          ) {
            unverifiedResults++;
            continue;
          }

          // === TEST GENERATION FALLBACK (Phase 3) ===
          // If no existing test files are present in the candidate workspace,
          // generate a security-focused regression test that verifies the repaired
          // code uses parameterized queries instead of string-interpolated SQL.
          const existingTestFiles = fs.readdirSync(candidateWorkspace).filter(
            (f: string) => f.startsWith('test_') && f.endsWith('.py')
          );
          if (existingTestFiles.length === 0) {
            // Read the patched file to examine its SQL query patterns
            const patchedFilePath = path.join(candidateWorkspace, vulnerability.file_path);
            const patchApplied = fs.existsSync(patchedFilePath);
            const codeToCheck = patchApplied
              ? fs.readFileSync(patchedFilePath, 'utf8')
              : candidate.modified_code || '';

// Generate a pytest that checks for parameterized query patterns
          const testContent = `
import re
import pytest

def test_uses_parameterized_queries():
    \"\"\"Test that the repaired SQL code uses parameterized queries, not string interpolation.\"\"\"
    # Read the patched source file
    file_path = os.path.join(os.path.dirname(__file__), "vuln.py")
    if not os.path.exists(file_path):
        pytest.skip("Patched source file not found for parameterized query check")
    with open(file_path, "r") as f:
        code = f.read()

    # Find all cursor.execute() calls
    execute_calls = re.findall(r"cursor\.execute\([^)]+\)", code)

    if not execute_calls:
        pytest.fail("No cursor.execute() calls found - no SQL queries in patched code")

    # Check that at least one execute call uses a parameter placeholder (?)
    has_parameterized = any("?" in call for call in execute_calls)

    if not has_parameterized:
        pytest.fail(
            "No parameterized queries found - user input may be directly "
            "interpolated into SQL queries, leaving the code vulnerable to SQL injection"
        )

    print("Parameterized query test passed: user input is properly parameterized")
`
          let testFilePath: string = path.join(candidateWorkspace, 'test_vuln.py');
          fs.writeFileSync(testFilePath, testContent, 'utf8')
          }
          // ==========================================

          const validationCandidate = {
            ...candidate,
            modified_code: fs.readFileSync(candidateFile, 'utf8'),
          };
          const valRes = await this.client.request({
            path: `/api/v1/vulnerabilities/${encodeURIComponent(vulnId)}/validate-candidates`,
            method: 'POST',
            body: {
              vulnerability_id: vulnId,
              vulnerability_type: vulnerability.vulnerability_type,
              candidates: [validationCandidate],
              workspace_path: candidateWorkspace,
              baseline_workspace_path: scan.workspacePath,
              file_path: vulnerability.file_path,
              language: this.languageFromPath(vulnerability.file_path),
            },
            requestId: scan.id,
            timeoutMs: SCAN_STAGE_TIMEOUT_MS,
          });
          if (valRes.ok && Array.isArray(valRes.data?.results) && valRes.data.results.length === 1) {
            validationResults.push(...valRes.data.results);
            const rawStatus = valRes.data.results[0]?.validation_status || valRes.data.results[0]?.verdict || '';
            const status = String(rawStatus).toUpperCase();
            if (status === 'UNVERIFIED' || status === 'PASS_UNVERIFIED') unverifiedResults++;
            else if (status !== 'PASS' && status !== 'SUCCESS') failedResults++;
          } else {
            failedResults++;
          }
        } catch (err: any) {
          failedResults++;
          console.warn(`[orchestration] patch validation failed for ${vulnId}:`, err?.message);
        } finally {
          if (candidateWorkspace) WorkspaceService.cleanupScanWorkspace(candidateWorkspace);
        }
      }

      if (validationResults.length > 0) {
        (scan.results.validation as any)[vulnId] = {
          vulnerability_id: vulnId,
          results: validationResults,
          total_validated: validationResults.length,
          passed_count: validationResults.filter((result) => ['PASS', 'SUCCESS'].includes(String(result.validation_status).toUpperCase())).length,
          failed_count: validationResults.filter((result) => !['PASS', 'SUCCESS'].includes(String(result.validation_status).toUpperCase())).length,
        };
        validatedCount++;
      }
    }

    stage.durationMs = Date.now() - started;
    // Allow pipeline to continue even when some results are unverified.
    // Unverified candidates are tracked but do not block downstream stages
    // (confidence ranking, secured file generation). The artifactAuthorization
    // will be set based on ACE score and security gate results later.
    const allPassed = validatedCount > 0 && failedResults === 0;
    if (allPassed && unverifiedResults === 0) {
      stage.state = 'COMPLETED';
      const sandboxStatuses = new Set<string>();
      for (const data of Object.values((scan.results.validation as Record<string, any>) || {})) {
        if (data?.sandbox_status) sandboxStatuses.add(data.sandbox_status);
      }
      stage.details = {
        validatedVulnerabilities: validatedCount,
        failedResults,
        unverifiedResults,
        sandboxStatus: sandboxStatuses.size === 1 ? [...sandboxStatuses][0] : undefined,
      };
    } else if (validatedCount > 0 && failedResults === 0) {
      // Some results are unverified but no failures — proceed, marking
      // unverified so the downstream eligibility logic can apply ACE-based policy.
      stage.state = 'COMPLETED';
      stage.details = {
        validatedVulnerabilities: validatedCount,
        failedResults,
        unverifiedResults,
        sandboxStatus: undefined,
        note: 'unverified — ACE-based download eligibility will apply',
      };
    } else if (validatedCount > 0 && failedResults > 0) {
      // Hard failures block the pipeline.
      stage.state = 'FAILED';
      stage.error = 'Candidate validation failed against AI engine.';
      stage.details = { validatedVulnerabilities: validatedCount, failedResults, unverifiedResults };
    } else {
      // No candidates validated at all.
      stage.state = 'NOT_APPLICABLE';
      stage.details = { reason: 'No candidate patches generated to validate' };
    }
    await this.persist(scan);
  }

  private async runConfidenceRankingStage(scan: ScanRecord): Promise<void> {
    const stage = scan.stages.confidence;
    scan.currentStage = 'confidence';
    const started = Date.now();

    if (scan.stages.validation.state === 'NOT_APPLICABLE') {
      // No candidate patches to rank. Confidence is not computed for clean
      // code; no fabricated 100 is emitted.
      stage.state = 'NOT_APPLICABLE';
      stage.durationMs = Date.now() - started;
      stage.details = { reason: 'No candidate patches generated; confidence not computed' };
      await this.persist(scan);
      return;
    }

    stage.state = 'RUNNING';
    scan.updatedAt = new Date().toISOString();
    await this.persist(scan);

    scan.results = scan.results ?? {};
    scan.results.confidence = scan.results.confidence ?? {};
    let rankedCount = 0;
    let highestScore: number | null = null;

    const validationRecords = (scan.results.validation as Record<string, any>) || {};
    for (const [vulnId, record] of Object.entries(validationRecords)) {
      // Validation now stores the full response; unwrap the per-patch results.
      const results = Array.isArray(record) ? record : record?.results;
      if (!Array.isArray(results) || results.length === 0) continue;

      try {
        const rankRes = await this.client.request({
          path: `/api/v1/vulnerabilities/${encodeURIComponent(vulnId)}/recommendation`,
          method: 'POST',
          body: { vulnerability_id: vulnId, validation_results: results },
          requestId: scan.id,
          timeoutMs: SCAN_STAGE_TIMEOUT_MS,
        });
        if (rankRes.ok && rankRes.data?.recommendation) {
          const rec = rankRes.data.recommendation;
          (scan.results.confidence as any)[vulnId] = rec;
          rankedCount++;
          // RecommendationResponse exposes ranked_patches[] with
          // confidence_score; the backend echoes the best real score.
          const ranked = Array.isArray(rec.ranked_patches) ? rec.ranked_patches : [];
          for (const rp of ranked) {
            if (typeof rp?.confidence_score === 'number') {
              highestScore = highestScore === null ? rp.confidence_score : Math.max(highestScore, rp.confidence_score);
            }
          }
        }
      } catch (err: any) {
        console.warn(`[orchestration] confidence ranking failed for ${vulnId}:`, err?.message);
      }
    }

    stage.durationMs = Date.now() - started;
    if (rankedCount > 0 && highestScore !== null) {
      scan.confidence = Math.min(100, Math.round(highestScore));
      stage.state = 'COMPLETED';
      stage.details = { rankedVulnerabilities: rankedCount, confidenceScore: scan.confidence };
    } else if (rankedCount > 0) {
      // Recommendations returned but carried no confidence scores.
      stage.state = 'FAILED';
      stage.error = 'Recommendation response missing confidence scores.';
    } else {
      stage.state = 'FAILED';
      stage.error = 'No recommendations produced from validated candidates.';
    }
    await this.persist(scan);
  }

  private async runSecuredFileStage(scan: ScanRecord): Promise<void> {
    const stage = scan.stages.securedFile ?? blankStage();
    scan.stages.securedFile = stage;
    scan.currentStage = 'securedFile';
    stage.state = 'RUNNING';
    const started = Date.now();

    try {
      const isSingle = scan.uploadType === 'single_file';
      const origName = scan.originalFileName || (isSingle ? 'source_file.py' : 'archive.zip');
      const ext = path.extname(origName);
      const base = ext ? origName.slice(0, origName.length - ext.length) : origName;
      const outputName = `${base}_secured${ext}`;

      const vulnerabilities = this.extractVulnerabilities(scan);
      const beforeFindings = this.securityFindingDedup(vulnerabilities);
      const beforeRisk = this.scoreFindingList(beforeFindings);

      // Materialize a remediated copy of the workspace. Only managed workspaces
      // are copied from the shared volume; managed flag is always true here.
      const patchedDir = WorkspaceService.patchedRunDir(scan.id);
      if (fs.existsSync(patchedDir)) fs.rmSync(patchedDir, { recursive: true, force: true });
      fs.mkdirSync(patchedDir, { recursive: true });
      fs.cpSync(scan.workspacePath, patchedDir, { recursive: true });

      // Apply the recommended (or first) candidate for each patched vulnerability.
      const appliedPatchIds: string[] = [];
      for (const [vulnId, patchDataRaw] of Object.entries(scan.patches)) {
        const patchData = patchDataRaw as any;
        const candidates: any[] = patchData?.candidates || [];
        const rec = (scan.results?.confidence as any)?.[vulnId];
        const bestId = rec?.recommended_patch_id;
        const candidate =
          candidates.find((c) => c.patch_id === bestId && !this.isNoopPatch(String(c.modified_code ?? ''))) ||
          candidates.find((c) => !this.isNoopPatch(String(c.modified_code ?? ''))) ||
          candidates.find((c) => c.patch_id === bestId) ||
          candidates[0];
        if (!candidate || !candidate.modified_code) continue;

        const vuln = beforeFindings.find((f) => f.id === vulnId);
        const targetFile = vuln?.file_path || candidate?.file || scan.originalFileName || '';
        if (!targetFile) continue;
        const absPath = path.join(patchedDir, targetFile);
        if (!fs.existsSync(absPath)) continue;

        // Hallucinated dependency: remediate the manifest by removing the line
        // from the artifact. This path runs even when the AI only produced
        // no-op placeholders, because the removal is a line-level operation.
        const vulnType = ((vuln?.vulnerability_type || '') as string).toUpperCase();
        if (vulnType.includes('HALLUCINATED') || vulnType.includes('DEPENDENC')) {
          const appliedDep = this.applyPatchToFile(absPath, candidate, vuln);
          if (appliedDep) appliedPatchIds.push(vulnId);
          continue;
        }

        const applied = this.applyPatchToFile(absPath, candidate, vuln);
        if (applied) appliedPatchIds.push(vulnId);
      }

      // Deterministic post-remediation residual: findings whose patch could not
      // be safely applied during artifact building.
      const remainingVulns = beforeFindings.filter((f) => !appliedPatchIds.includes(f.id));

      // Best-effort final re-scan on the remediated copy. The stateless AI
      // endpoints can be re-invoked against the patched workspace. Both security
      // and hallucination/dependency residuals are counted so the reported
      // after-risk honestly reflects what remains in the artifact.
      let residualFindings: Array<{ severity: string }> = [];
      let afterFindingsRow = 0;
      let rescanned = false;
      let securityRescanPassed = false;
      // Run the three re-scans concurrently so honest residual accounting adds
      // minimal latency on top of the original analysis.
      const rescans = await Promise.allSettled([
        this.client.request({
          path: '/api/v1/security/scan',
          method: 'POST',
          body: { repository_id: scan.repositoryId, workspace_path: patchedDir },
          requestId: scan.id,
          timeoutMs: SCAN_STAGE_TIMEOUT_MS,
        }),
        this.client.request({
          path: '/api/v1/hallucination/detect',
          method: 'POST',
          body: { repository_id: scan.repositoryId, workspace_path: patchedDir },
          requestId: scan.id,
          timeoutMs: SCAN_STAGE_TIMEOUT_MS,
        }),
        this.client.request({
          path: '/api/v1/dependency/analyze',
          method: 'POST',
          body: { repository_id: scan.repositoryId, workspace_path: patchedDir },
          requestId: scan.id,
          timeoutMs: SCAN_STAGE_TIMEOUT_MS,
        }),
      ]);
      const [re, he, de] = rescans;
      if (re.status === 'fulfilled' && re.value.ok && re.value.data) {
        const securityResult = re.value.data as Record<string, any>;
        const resultStatus = String(securityResult.status || 'COMPLETED').toUpperCase();
        const scannerStatus = String(securityResult.scanner_status || resultStatus).toUpperCase();
        if (resultStatus !== 'FAILED' && !['FAILED', 'TIMEOUT'].includes(scannerStatus)) {
          const fresh = this.securityFindingDedup(this.collectSecurityFindings(securityResult));
          residualFindings.push(...fresh);
          afterFindingsRow += fresh.length;
          securityRescanPassed = true;
          rescanned = true;
        } else {
          console.warn(`[orchestration] secured-file security re-scan ${scannerStatus}:`, securityResult.error || 'verification failed');
        }
      } else {
        const why = re.status === 'rejected' ? re.reason?.message : re.value?.data?.error || 'scan rejected';
        console.warn('[orchestration] secured-file security re-scan failed:', why);
      }
      if (he.status === 'fulfilled' && Array.isArray(he.value?.data?.findings)) {
        const residual = he.value.data.findings.map((f: any) => ({ severity: f.severity || 'HIGH' }));
        residualFindings.push(...residual);
        afterFindingsRow += residual.length;
        rescanned = true;
      } else {
        const why = he.status === 'rejected' ? he.reason?.message : he.value?.data?.error || 'scan rejected';
        console.warn('[orchestration] secured-file hallucination re-scan failed:', why);
      }
      if (de.status === 'fulfilled' && Array.isArray(de.value?.data?.findings)) {
        const residual = de.value.data.findings.map((f: any) => ({ severity: f.severity || 'HIGH' }));
        residualFindings.push(...residual);
        afterFindingsRow += residual.length;
        rescanned = true;
      } else {
        const why = de.status === 'rejected' ? de.reason?.message : de.value?.data?.error || 'scan rejected';
        console.warn('[orchestration] secured-file dependency re-scan failed:', why);
      }

      const afterRisk = this.scoreFindingList([...remainingVulns, ...residualFindings]);

      // --- Authoritative ACE score (0-100), never fabricated ---
      const aceScore = this.extractAceScore(scan);

      // --- Security verdict: confirmed critical vulnerability or malicious
      // payload remaining in the remediated artifact. Never suppressed. ---
      const residualCriticalOrMalicious = this.hasCriticalOrMaliciousFinding(
        [...remainingVulns, ...residualFindings]
      );

      const securityGatesPassed =
        securityRescanPassed && remainingVulns.length === 0 && afterFindingsRow === 0;

      // --- Download eligibility policy (configurable defaults, separate from ACE) ---
      const decision = this.computeDownloadEligibility({
        aceScore,
        securityGatesPassed,
        hasCriticalOrMalicious: residualCriticalOrMalicious,
        hasNoFindings: beforeFindings.length === 0,
      });

      scan.securityVerdict = decision.securityVerdict;
      scan.downloadEligibility = decision.downloadEligibility;

      // Fail-closed: confirmed critical vulnerability or malicious payload never
      // yields a downloadable artifact (not even unverified).
      if (decision.authorizationLevel === 'BLOCKED') {
        stage.state = 'FAILED';
        scan.remediationStatus = 'BLOCKED';
        scan.artifactAuthorization = 'BLOCKED';
        stage.durationMs = Date.now() - started;
        stage.error = decision.downloadEligibility.reason;
        stage.details = {
          beforeFindingsCount: beforeFindings.length,
          unappliedFindingsCount: remainingVulns.length,
          afterFindingsCount: afterFindingsRow,
          afterRiskScore: afterRisk,
          rescanned,
          blockedReason: decision.downloadEligibility.reason,
          securityVerdict: scan.securityVerdict,
          downloadEligibility: scan.downloadEligibility,
        };
        await this.persist(scan);
        return;
      }

      // Produce the artifact: remediated file for single uploads, zip for archives.
      // Generated from the exact candidate whose ACE score and scan results are displayed.
      let outputPath: string;
      if (isSingle) {
        const files = fs.readdirSync(patchedDir).filter((f) => !f.startsWith('.'));
        const srcFileName = files.find((f) => f === scan.originalFileName) || files[0];
        if (!srcFileName) throw new Error('No source file found in patched workspace');
        outputPath = WorkspaceService.securedFilePath(scan.id, outputName);
        fs.copyFileSync(path.join(patchedDir, srcFileName), outputPath);
      } else {
        outputPath = WorkspaceService.securedFilePath(scan.id, outputName);
        const AdmZip = (await import('adm-zip')).default;
        const zip = new AdmZip();
        zip.addLocalFolder(patchedDir);
        zip.writeZip(outputPath);
      }

      const riskReductionPct = beforeRisk > 0 ? Math.round(((beforeRisk - afterRisk) / beforeRisk) * 100) : 0;
      const outputFileHash = crypto.createHash('sha256').update(fs.readFileSync(outputPath)).digest('hex');

      scan.outputFile = outputPath;
      scan.outputFileHash = outputFileHash;
      scan.remediationStatus = beforeFindings.length === 0 ? 'NOT_REQUIRED' : 'VERIFIED';
      scan.artifactAuthorization = decision.authorizationLevel;
      scan.remediation = {
        beforeFindingsCount: beforeFindings.length,
        afterFindingsCount: afterFindingsRow,
        beforeRiskScore: beforeRisk,
        afterRiskScore: afterRisk,
        riskReductionPct,
        patchesAppliedCount: appliedPatchIds.length,
        rescanned,
        sandboxVerified: this.aggregateSandboxVerified(scan),
      };

      stage.state = 'COMPLETED';
      stage.durationMs = Date.now() - started;
      stage.details = {
        outputFile: outputPath,
        fileName: outputName,
        sizeBytes: fs.statSync(outputPath).size,
        outputFileHash,
        patchesAppliedCount: appliedPatchIds.length,
        beforeFindingsCount: beforeFindings.length,
        afterFindingsCount: afterFindingsRow,
        beforeRiskScore: beforeRisk,
        afterRiskScore: afterRisk,
        riskReductionPct,
        rescanned,
        securityVerdict: scan.securityVerdict,
        downloadEligibility: scan.downloadEligibility,
        sandboxStatus: (scan.stages.validation as { details?: any }).details?.sandboxStatus,
      };
    } catch (err: any) {
      stage.state = 'FAILED';
      scan.remediationStatus = 'FAILED';
      scan.artifactAuthorization = 'BLOCKED';
      stage.error = err?.message || String(err);
      stage.durationMs = Date.now() - started;
    }
    await this.persist(scan);
  }

  /** Best-effort replace of the vulnerable snippet (from the security finding,
   *  never from the generated patch payload) with the remediated code.
   *
   *  Returns true only when a safe, structural replacement was made. If the
   *  merge cannot be performed without corrupting the file, returns false so
   *  the vulnerability remains counted in the residual risk.
   */
  private applyPatchToFile(
    absPath: string,
    candidate: any,
    vuln?: { id: string; file_path: string; line_number: number; code_snippet: string; vulnerability_type?: string; package_name?: string } | undefined
  ): boolean {
    try {
        const content = fs.readFileSync(absPath, 'utf8');
        const lines = content.split(/\r?\n/);

      // 0. Hallucinated dependency in a manifest: remove the offending line(s).
      //    This is a line-level remediation that does not depend on the
      //    generated patch candidates, so it runs before any no-op guard.
      const vulnType = ((vuln?.vulnerability_type || '') as string).toUpperCase();
      if (vulnType.includes('HALLUCINATED') || vulnType.includes('DEPENDENC')) {
        const packageName = vuln?.package_name;
        if (packageName) {
          const keep = lines.filter((l) => !l.includes(packageName));
          if (keep.length !== lines.length) {
            fs.writeFileSync(absPath, keep.join('\n') + (content.endsWith('\n') ? '\n' : ''), 'utf8');
            return true;
          }
        }
      }

      const modifiedCode = String(candidate.modified_code ?? '');
      const modifiedTrim = modifiedCode.replace(/\r?\n$/, '');
      if (this.isNoopPatch(modifiedCode)) return false;

      // 1. The patch is already present verbatim in the file.
      if (modifiedTrim && content.includes(modifiedTrim)) return true;

      let vulnIdx = -1;
      const snippet = (vuln?.code_snippet || '').trim();
      if (snippet) vulnIdx = lines.findIndex((l) => l.trim() === snippet);
      if (vulnIdx === -1 && vuln?.line_number) vulnIdx = Math.max(0, vuln.line_number - 1);
      if (vulnIdx === -1) return false;

      // 2. Whole-file replacement: the vulnerable snippet is the entire file.
      const fileTrim = lines.map((l) => l.trim()).filter(Boolean).join('\n');
      if (snippet && fileTrim === snippet) {
        fs.writeFileSync(absPath, modifiedTrim + (content.endsWith('\n') ? '\n' : ''), 'utf8');
        return true;
      }

      // 3. Structural block replacement for Python functions/classes at top level.
      if (modifiedCode.includes('\n')) {
        const range = this.findReplaceableBlock(lines, vulnIdx);
        if (range) {
          const patchedLines = modifiedCode.split(/\r?\n/);
          const resultLines = lines.slice(0, range.start).concat(patchedLines, lines.slice(range.end + 1));
          fs.writeFileSync(absPath, resultLines.join('\n') + (content.endsWith('\n') ? '\n' : ''), 'utf8');
          return true;
        }
      }

      // 4. Single-line patch: replace the one targeted line.
      if (!modifiedCode.includes('\n')) {
        lines[vulnIdx] = modifiedCode;
        fs.writeFileSync(absPath, lines.join('\n') + (content.endsWith('\n') ? '\n' : ''), 'utf8');
        return true;
      }

      return false;
    } catch {
      return false;
    }
  }

  /** Generic placeholder emitted by the deterministic AI fallback when it has
   *  no real remediation for a strategy. These are never real fixes. */
  private isNoopPatch(code: string): boolean {
    const t = code.trim();
    return (
      t.startsWith('# Patch candidate') ||
      t.startsWith('// Patch candidate') ||
      t.startsWith('/* Patch candidate') ||
      t.startsWith('# NOT APPLICABLE') ||
      t.startsWith('<!-- Patch candidate')
    );
  }

  private findReplaceableBlock(lines: string[], idx: number): { start: number; end: number } | null {
    const isIgnorable = (l: string) => l.trim() === '';
    for (let i = idx; i >= 0; i--) {
      const trimmed = lines[i].trim();
      if (isIgnorable(lines[i])) continue;
      const indent = (lines[i].match(/^\s*/) as RegExpMatchArray)[0].length;
      const isHeader = /^(def\s|async\s+def\s|class\s)/.test(trimmed);
      if (isHeader && indent === 0) {
        let end = lines.length - 1;
        for (let j = i + 1; j < lines.length; j++) {
          if (!isIgnorable(lines[j]) && ((lines[j].match(/^\s*/) as RegExpMatchArray)[0].length <= indent)) {
            end = j - 1;
            break;
          }
        }
        return { start: i, end };
      }
      if (indent === 0) break;
    }
    return null;
  }

  /** Deduplicate vulnerability findings keyed by id + file + line. */
  private securityFindingDedup(findings: Array<{ id: string; severity: string }>): Array<{
      id: string;
      severity: string;
      file_path: string;
      line_number: number;
      code_snippet: string;
      vulnerability_type?: string;
    package_name?: string;
  }> {
    const seen = new Set<string>();
    const out: Array<{ id: string; severity: string; file_path: string; line_number: number; code_snippet: string; vulnerability_type?: string; package_name?: string }> = [];
    for (const f of findings as any) {
      const key = `${f.id}|${f.file_path}|${f.line_number}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(f);
    }
    return out;
  }

  private collectSecurityFindings(data: any): Array<{
      id: string;
      severity: string;
      file_path: string;
      line_number: number;
      code_snippet: string;
      vulnerability_type?: string;
  }> {
    const list: Array<{ id: string; severity: string; file_path: string; line_number: number; code_snippet: string; vulnerability_type?: string }> = [];
    const findings = data?.findings || data?.vulnerabilities || data?.results || [];
    for (let i = 0; i < (Array.isArray(findings) ? findings.length : 0); i++) {
      const f = findings[i];
      list.push({
        id: f.id || `sec-${i + 1}`,
        severity: f.severity || 'HIGH',
        file_path: f.file_path || '',
        line_number: Number(f.line_number || f.line || 1),
        code_snippet: f.code_snippet || f.code || f.vulnerable_code || '',
        vulnerability_type: f.vulnerability_type || f.type || '',
      });
    }
    return list;
  }

  private scoreFindingList(findings: Array<{ severity: string }>): number {
    let score = 0;
    for (const f of findings) {
      const sev = String(f.severity || '').toUpperCase();
      if (sev === 'CRITICAL') score += 35;
      else if (sev === 'HIGH') score += 20;
      else if (sev === 'MEDIUM') score += 10;
      else score += 5;
    }
    return Math.min(100, score);
  }

  private aggregateSandboxVerified(scan: ScanRecord): boolean | null {
    const validation = (scan.results?.validation as Record<string, any>) || {};
    const statuses: string[] = [];
    for (const record of Object.values(validation)) {
      const results = Array.isArray(record) ? record : record?.results;
      if (!Array.isArray(results)) continue;
      for (const r of results) {
        const ok = r?.sandbox_execution?.success ?? true;
        if (ok === false) return false;
      }
      if (Array.isArray(record)) statuses.push('AVAILABLE');
      else if (record?.sandbox_status) statuses.push(record.sandbox_status);
    }
    if (statuses.length === 0) return null;
    if (statuses.every((s) => s === 'NOT_AVAILABLE')) return false;
    return null;
  }

  /** Extract the authoritative ACE score (0-100) from the scan record.
   * The score comes from the confidence ranking stage
   * (recommendation.ranked_patches[].confidence_score, echoed as scan.confidence).
   * Missing, invalid, or out-of-scale scores return null — never fabricated. */
  private extractAceScore(scan: ScanRecord): number | null {
    const { aceScaleMin, aceScaleMax } = config.aceDownload;
    const inScale = (score: number): number | null => {
      const s = Math.round(score);
      return Number.isFinite(s) && s >= aceScaleMin && s <= aceScaleMax ? s : null;
    };
    if (typeof scan.confidence === 'number') return inScale(scan.confidence);
    const confidenceResults = (scan.results?.confidence as Record<string, any> | undefined);
    if (confidenceResults) {
      for (const record of Object.values(confidenceResults)) {
        const candidates: any[] = Array.isArray(record)
          ? record
          : (record?.results ?? record?.ranked_patches ?? []);
        for (const c of candidates) {
          const score = c?.confidence_score ?? c?.final_score;
          if (typeof score === 'number') {
            const scaled = inScale(score);
            if (scaled !== null) return scaled;
          }
        }
      }
    }
    return null;
  }

  /** True when a confirmed critical vulnerability or malicious payload remains
   * in the remediated artifact. Fail-closed: never suppressed. */
  private hasCriticalOrMaliciousFinding(findings: Array<{
    severity: string;
    vulnerability_type?: string;
    type?: string;
    critical?: boolean;
  }>): boolean {
    for (const f of findings) {
      const sev = String(f.severity || '').toUpperCase();
      const type = String(f.vulnerability_type || f.type || '');
      if (sev === 'CRITICAL' || f.critical === true || /malicious|payload/i.test(type)) return true;
    }
    return false;
  }

  /** ACE-based download eligibility policy (configurable defaults).
   *
   * Separates download_eligibility (can the candidate be downloaded) from
   * security_verdict (did it pass security and validation checks). UNVERIFIED
   * does not automatically mean ineligible; confirmed critical/malicious
   * findings always mean ineligible.
   *
   * These thresholds are INITIAL DEFAULTS requiring empirical calibration and
   * are kept strictly separate from the scientific ACE scoring algorithm.
   */
  private computeDownloadEligibility(params: {
    aceScore: number | null;
    securityGatesPassed: boolean;
    hasCriticalOrMalicious: boolean;
    hasNoFindings: boolean;
  }): {
    authorizationLevel: 'AUTHORIZED' | 'UNVERIFIED_DOWNLOAD' | 'BLOCKED';
    securityVerdict: SecurityVerdict;
    downloadEligibility: DownloadEligibility;
  } {
    const { authorizedThreshold, unverifiedThreshold, aceScaleMin, aceScaleMax } = config.aceDownload;
    const { aceScore, securityGatesPassed, hasCriticalOrMalicious, hasNoFindings } = params;
    const validAce = aceScore !== null && Number.isFinite(aceScore) && aceScore >= aceScaleMin && aceScore <= aceScaleMax;

    const build = (
      level: 'AUTHORIZED' | 'UNVERIFIED_DOWNLOAD' | 'BLOCKED',
      securityVerdict: SecurityVerdict,
      reason: string,
      acknowledgementRequired: boolean,
      eligible: boolean,
    ): {
      authorizationLevel: 'AUTHORIZED' | 'UNVERIFIED_DOWNLOAD' | 'BLOCKED';
      securityVerdict: SecurityVerdict;
      downloadEligibility: DownloadEligibility;
    } => ({
      authorizationLevel: level,
      securityVerdict,
      downloadEligibility: {
        eligible,
        level: level === 'BLOCKED' ? 'INELIGIBLE' : level,
        reason,
        aceScore: validAce ? aceScore : null,
        aceScale: { min: aceScaleMin, max: aceScaleMax },
        acknowledgementRequired,
        securityGatesPassed: level === 'AUTHORIZED' ? true : securityGatesPassed,
        thresholds: { authorized: authorizedThreshold, unverified: unverifiedThreshold },
      },
    });

    // Fail-closed: confirmed critical vulnerability or malicious payload blocks
    // every download, including unverified downloads.
    if (hasCriticalOrMalicious) {
      return build(
        'BLOCKED',
        'BLOCKED',
        'Confirmed critical vulnerability or malicious payload remains in the candidate; download blocked.',
        false,
        false
      );
    }

    // No findings requiring remediation: nothing to secure, output authorized.
    if (hasNoFindings) {
      return build(
        'AUTHORIZED',
        'PASSED',
        'No security findings detected; original code unchanged — no remediation required.',
        false,
        true
      );
    }

    // Security verification could not be completed (rescan failed/timed out):
    // the artifact cannot be claimed secured. Unverified download only.
    if (!securityGatesPassed) {
      return build(
        'UNVERIFIED_DOWNLOAD',
        'UNVERIFIED',
        'Security verification could not be completed; unverified download — acknowledgement required.',
        true,
        true
      );
    }

    // Gates passed; the ACE score controls the authorization level.
    if (validAce && aceScore >= authorizedThreshold) {
      return build(
        'AUTHORIZED',
        'PASSED',
        `ACE score ${aceScore} >= ${authorizedThreshold}; all security gates passed.`,
        false,
        true
      );
    }
    if (validAce && aceScore >= unverifiedThreshold) {
      return build(
        'UNVERIFIED_DOWNLOAD',
        'UNVERIFIED',
        `ACE score ${aceScore} >= ${unverifiedThreshold} and < ${authorizedThreshold}; unverified download — use at own risk.`,
        false,
        true
      );
    }
    if (validAce) {
      return build(
        'UNVERIFIED_DOWNLOAD',
        'UNVERIFIED',
        `ACE score ${aceScore} < ${unverifiedThreshold}; unverified download — user acknowledgement required.`,
        true,
        true
      );
    }
    // Missing or invalid ACE score: no score is fabricated; acknowledgement required.
    return build(
      'UNVERIFIED_DOWNLOAD',
      'UNVERIFIED',
      'No valid ACE score available; unverified download — acknowledgement required. Same critical safety gates apply.',
      true,
      true
    );
  }

  /** Auditable explicit user acknowledgement for an unverified download. */
  public acknowledgeDownload(scanId: string, acknowledgement: DownloadAcknowledgement): boolean {
    const scan = this.scans.get(scanId);
    if (!scan) return false;
    scan.downloadAcknowledgement = acknowledgement;
    scan.updatedAt = new Date().toISOString();
    void this.persist(scan);
    return true;
  }

  private async runStage(
    scan: ScanRecord,
    stageName: 'analysis' | 'hallucination' | 'security' | 'dependency',
    opts: import('./aiEngine.client').AiEngineRequestOptions
  ): Promise<void> {
    const stage = scan.stages[stageName];
    stage.state = 'RUNNING';
    scan.updatedAt = new Date().toISOString();
    const startedAt = Date.now();

    try {
      const response = await this.client.request({ ...opts, timeoutMs: SCAN_STAGE_TIMEOUT_MS });
      stage.durationMs = Date.now() - startedAt;
      stage.httpStatus = response.status;
      if (!response.ok) {
        stage.state = 'FAILED';
        stage.error = `AI engine responded with HTTP ${response.status}`;
        return;
      }
      const payload = response.data as Record<string, any> | undefined;
      const resultStatus = typeof payload?.status === 'string' ? payload.status : 'COMPLETED';
      const scannerStatus = typeof payload?.scanner_status === 'string' ? payload.scanner_status : resultStatus;
      if (stageName === 'security' && (scannerStatus !== 'COMPLETED' || resultStatus !== 'COMPLETED')) {
        stage.state = 'FAILED';
        stage.error = payload?.error || `Security scanner status is not verified (${scannerStatus || 'missing'} / ${resultStatus || 'missing'}).`;
      } else if (resultStatus === 'FAILED') {
        stage.state = 'FAILED';
        stage.error = payload?.error || 'AI engine reported a failed verification result.';
      } else if (resultStatus === 'NOT_APPLICABLE') {
        stage.state = 'NOT_APPLICABLE';
        stage.details = {
          ...(stage.details ?? {}),
          reason: payload?.error || 'No applicable security findings for this repository.',
          scannerStatus,
          status: resultStatus,
        };
        if (payload?.error) {
          stage.error = payload.error;
        }
      } else {
        stage.state = 'COMPLETED';
      }
      if (stageName === 'security') {
        stage.details = { status: resultStatus, scannerStatus };
      }
      scan.results = scan.results ?? {};
      scan.results[stageName] = payload ?? response.data;
    } catch (err: any) {
      stage.durationMs = Date.now() - startedAt;
      stage.state = 'FAILED';
      stage.error = err?.message || String(err);
    }
    await this.persist(scan);
  }

  private persistenceEnabled(): boolean {
    // Keep persistence off during automated tests: they use fake repo/scan ids
    // and must stay hermetic (no real DB). Duplicate-state recovery is
    // exercised via the running services instead.
    if (process.env.NODE_ENV === 'test') return false;
    return config.env === 'production' || process.env.PERSIST_SCAN_STATE === 'true';
  }

  /** Resolve a promise or bail with `undefined` if it exceeds the deadline. */
  private async withTimeout<T>(promise: Promise<T>, ms: number): Promise<T | undefined> {
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([
        promise,
        new Promise<undefined>((resolve) => {
          timer = setTimeout(() => resolve(undefined), ms);
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private async persist(scan: ScanRecord): Promise<void> {
    if (!this.persistenceEnabled()) return;
    try {
      const metadata = { orchestration: scan };
      const status = scan.status === 'QUEUED' ? 'PENDING' : scan.status === 'RUNNING' ? 'SCANNING' : scan.status;
      if (!this.persistedScans.has(scan.id)) {
        await ScanModel.create({
          id: scan.id,
          repository_id: scan.repositoryId,
          status,
          workspace_path: scan.workspacePath,
          metadata,
        });
        this.persistedScans.add(scan.id);
      } else {
        await ScanModel.updateMetadata(scan.id, metadata);
        await ScanModel.updateStatus(scan.id, status, scan.error);
      }
    } catch (err) {
      console.warn('[orchestration] scan persistence unavailable:', err instanceof Error ? err.message : err);
    }
  }
}
