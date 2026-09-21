export const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';
export const AI_URL = process.env.NEXT_PUBLIC_AI_ENGINE_URL || 'http://localhost:8000';

/* ------------------------------------------------------------------ */
/* Types (kept permissive — shapes come from FastAPI/Express models)  */
/* ------------------------------------------------------------------ */

export interface HealthInfo {
  service?: string;
  status?: string;
  version?: string;
  timestamp?: string;
  dependencies?: {
    database?: string;
    dbLatencyMs?: number | null;
  };
  llm_config?: {
    provider?: string;
    provider_name?: string;
    model?: string;
    api_key_configured?: boolean;
    llm_reachable?: boolean;
  };
}

export interface RuntimeEventRecord {
  event_id?: string;
  event_type?: string;
  severity?: string;
  source?: string;
  description?: string;
  endpoint?: string;
  method?: string;
  client_ip?: string;
  user_agent?: string;
  status_code?: number;
  response_time_ms?: number;
  request_count?: number;
  detected_at?: string;
}

export interface AlertRecord {
  alert_id?: string;
  event_type?: string;
  severity?: string;
  vulnerability_type?: string;
  vulnerability_description?: string;
  affected_endpoint?: string;
  risk_score?: number;
  recommended_action?: string;
  created_at?: string;
}

export interface MonitoringSummary {
  total_events?: number;
  total_alerts?: number;
  events_by_type?: Record<string, number>;
  events_by_severity?: Record<string, number>;
  alerts_by_severity?: Record<string, number>;
  recent_events?: RuntimeEventRecord[];
  recent_alerts?: AlertRecord[];
  top_anomaly_endpoints?: Array<{ endpoint?: string; count?: number }>;
  uptime_seconds?: number;
  last_event_at?: string | null;
}

export interface LearningSummary {
  total_records?: number;
  total_patterns?: number;
  patterns_count?: number;
  overall_acceptance_rate?: number;
  overall_deployment_success?: number;
  recent_adjustments?: unknown[];
  model_version?: string;
  adjustments_count?: number;
  [key: string]: unknown;
}

export interface ScanStageInfo {
  state?:
    | 'QUEUED'
    | 'RUNNING'
    | 'COMPLETED'
    | 'FAILED'
    | 'SKIPPED'
    | 'NOT_APPLICABLE'
    | 'PENDING'
    | 'SUCCESS'
    | string;
  durationMs?: number;
  error?: string;
  details?: Record<string, unknown>;
}

export interface ScanStages {
  repository?: ScanStageInfo;
  analysis?: ScanStageInfo;
  hallucination?: ScanStageInfo;
  dependency?: ScanStageInfo;
  security?: ScanStageInfo;
  risk?: ScanStageInfo;
  patch?: ScanStageInfo;
  validation?: ScanStageInfo;
  confidence?: ScanStageInfo;
  runtime?: ScanStageInfo;
  securedFile?: ScanStageInfo;
}

export interface ScanStatusPayload {
  success?: boolean;
  scanId?: string;
  repositoryId?: string;
  status?: string;
  currentStage?: string;
  stages?: ScanStages;
  error?: string | null;
  createdAt?: string;
  updatedAt?: string;
  completedAt?: string | null;
  // Authoritative pipeline artifacts — populated by the backend.
  hallucinationFindings?: unknown;
  securityFindings?: unknown;
  dependencyFindings?: unknown;
  riskAssessment?: RiskAssessment | null;
  riskScore?: number | null;
  riskLevel?: string | null;
  confidence?: number | null;
  patches?: Record<string, unknown>;
  validationResults?: Record<string, unknown>;
  remediation?: RemediationSummary | null;
  hasOutputFile?: boolean;
  downloadUrl?: string | null;
  outputFile?: string | null;
  securedFileName?: string | null;
  originalFileName?: string | null;
  uploadType?: string;
}

export interface FindingsPayload {
  success?: boolean;
  scanId?: string;
  repositoryId?: string;
  status?: string;
  stages?: ScanStages;
  hallucinationFindings?: unknown;
  securityFindings?: unknown;
  dependencyFindings?: unknown;
  riskAssessment?: RiskAssessment | null;
  riskScore?: number | null;
  riskLevel?: string | null;
  confidence?: number | null;
  patches?: Record<string, unknown>;
  validationResults?: Record<string, unknown>;
  remediation?: RemediationSummary | null;
  hasOutputFile?: boolean;
  downloadUrl?: string | null;
  outputFile?: string | null;
  securedFileName?: string | null;
  originalFileName?: string | null;
  uploadType?: string;
}

/** A security finding as reported by the backend security agent. */
export interface SecurityFinding {
  id?: string;
  vulnerability_type?: string;
  cwe_id?: string;
  severity?: string;
  file?: string;
  file_path?: string;
  line?: number;
  line_number?: number;
  code_snippet?: string;
  description?: string;
  reasoning?: string;
  evidence?: string;
  recommendation?: string;
  status?: string;
  [key: string]: unknown;
}

/** A hallucinated package/API as reported by the hallucination agent. */
export interface HallucinationFinding {
  id?: string;
  finding_id?: string;
  category?: string;
  symbol_name?: string;
  file_path?: string;
  line_number?: number;
  snippet?: string;
  confidence?: number;
  reasoning?: string;
  [key: string]: unknown;
}

export interface RiskAssessment {
  overall_risk_score?: number;
  overall_risk_level?: string;
  total_findings?: number;
  risk_factors?: unknown[];
  recommendations?: string[];
  [key: string]: unknown;
}

/** Final re-scan comparison produced by the backend after patch application. */
export interface RemediationSummary {
  rescanned: boolean;
  beforeFindingsCount: number;
  afterFindingsCount: number;
  beforeRiskScore: number;
  afterRiskScore: number;
  riskReductionPct: number;
  patchesAppliedCount: number;
  sandboxVerified: boolean;
  remediationSummary?: string;
  [key: string]: unknown;
}

export interface OutputArtifact {
  available: boolean;
  fileName?: string | null;
  downloadUrl?: string | null;
}

export function getSecuredFileDownloadUrl(repositoryId: string, scanId: string): string {
  return `${BACKEND_URL}/api/repositories/${encodeURIComponent(repositoryId)}/scan/${encodeURIComponent(scanId)}/download`;
}

/**
 * Download the real secured output produced by the backend pipeline.
 * Returns `true` on success; on failure returns `false` and the reason.
 */
export async function downloadSecuredFile(
  repositoryId: string,
  scanId: string
): Promise<{ ok: boolean; fileName?: string; error?: string }> {
  try {
    const res = await fetch(getSecuredFileDownloadUrl(repositoryId, scanId), { method: 'GET' });
    if (!res.ok) {
      return { ok: false, error: `Download failed (HTTP ${res.status}).` };
    }
    const blob = await res.blob();
    const disposition = res.headers.get('content-disposition') || '';
    const fileNameMatch = disposition.match(/filename="?([^"]+)"?/i);
    const fileName = fileNameMatch?.[1] || scanId;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    return { ok: true, fileName };
  } catch {
    return { ok: false, error: 'Network error during download. Check that the backend is running.' };
  }
}

export function extractFindings(value: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(value)) return value as Array<Record<string, unknown>>;
  if (!value || typeof value !== 'object') return [];
  const obj = value as { findings?: unknown; vulnerabilities?: unknown; results?: unknown };
  const raw = obj.findings ?? obj.vulnerabilities ?? obj.results;
  return Array.isArray(raw) ? (raw as Array<Record<string, unknown>>) : [];
}

export function totalVulnerabilities(value: unknown): number | null {
  if (!value || typeof value !== 'object') return null;
  const total = (value as { total_vulnerabilities?: number }).total_vulnerabilities;
  return typeof total === 'number' ? total : null;
}

export interface PatchRecord {
  patch_id?: string;
  vulnerability_id?: string;
  patch_strategy?: string;
  description?: string;
  status?: string;
  confidence?: number;
  [key: string]: unknown;
}

export interface PatchCandidate extends PatchRecord {
  modified_code?: string;
  explanation?: string;
  security_strategy?: string;
  assumptions?: string[];
  expected_effect?: string;
  potential_side_effects?: string[];
  is_not_applicable?: boolean;
}

export interface PatchGenerationPayload {
  vulnerability_id?: string;
  candidates?: PatchCandidate[];
  error?: string;
}

export interface ValidationPayload {
  vulnerability_id?: string;
  results?: unknown[];
  error?: string;
}

export interface ServiceStatus {
  service?: string;
  status?: string;
  version?: string;
}

export interface CommandCenterData {
  backendHealth: HealthInfo | null;
  aiHealth: HealthInfo | null;
  monitoring: MonitoringSummary | null;
  alerts: AlertRecord[];
  events: RuntimeEventRecord[];
  learningSummary: LearningSummary | null;
  scan: ScanStatusPayload | null;
  findings: FindingsPayload | null;
  patches: PatchRecord[];
  healthOk: { backend: boolean; ai: boolean };
}

/* ------------------------------------------------------------------ */
/* Fetch helpers                                                       */
/* ------------------------------------------------------------------ */

async function safeFetch(url: string, init?: RequestInit): Promise<Response | null> {
  try {
    const res = await fetch(url, init);
    return res;
  } catch (err) {
    console.warn(`[api] fetch failed: ${url}`, err);
    return null;
  }
}

async function safeGet<T>(url: string, signal?: AbortSignal): Promise<T | null> {
  const res = await safeFetch(url, { signal });
  if (!res || !res.ok) return null;
  try {
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

interface NamedList<T> {
  events?: T[];
  alerts?: T[];
  total?: number;
}

function toList<T>(payload: NamedList<T> | null | undefined): T[] {
  if (!payload) return [];
  if (Array.isArray(payload)) return payload as T[];
  const raw = payload.events ?? payload.alerts;
  return Array.isArray(raw) ? raw : [];
}

/* ------------------------------------------------------------------ */
/* Health / monitoring / learning / analytics                          */
/* ------------------------------------------------------------------ */

export async function fetchBackendHealth(signal?: AbortSignal): Promise<HealthInfo | null> {
  return safeGet<HealthInfo>(`${BACKEND_URL}/api/v1/health`, signal);
}

export async function fetchAiHealth(signal?: AbortSignal): Promise<HealthInfo | null> {
  return safeGet<HealthInfo>(`${AI_URL}/api/v1/health`, signal);
}

export async function fetchMonitoringSummary(signal?: AbortSignal): Promise<MonitoringSummary | null> {
  return safeGet<MonitoringSummary>(`${AI_URL}/api/v1/monitoring/summary`, signal);
}

export async function fetchMonitoringAlerts(signal?: AbortSignal): Promise<AlertRecord[]> {
  const payload = await safeGet<NamedList<AlertRecord>>(`${AI_URL}/api/v1/monitoring/alerts?limit=40`, signal);
  return toList(payload);
}

export async function fetchMonitoringEvents(signal?: AbortSignal): Promise<RuntimeEventRecord[]> {
  const payload = await safeGet<NamedList<RuntimeEventRecord>>(`${AI_URL}/api/v1/monitoring/events?limit=60`, signal);
  return toList(payload);
}

export async function fetchLearningSummary(signal?: AbortSignal): Promise<LearningSummary | null> {
  return safeGet<LearningSummary>(`${AI_URL}/api/v1/learning/summary`, signal);
}

/* ------------------------------------------------------------------ */
/* Scan workflow                                                       */
/* ------------------------------------------------------------------ */

export async function startScan(repositoryId: string): Promise<ScanStatusPayload | null> {
  const res = await safeFetch(`${BACKEND_URL}/api/repositories/${encodeURIComponent(repositoryId)}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  if (!res) return { error: 'Could not connect to the backend. Check that the backend service is running.' };
  try {
    const data = await res.json();
    if (!res.ok || !data.scanId) {
      return {
        repositoryId: data.repositoryId ?? repositoryId,
        status: data.status,
        error: data.error || `Backend rejected the scan request (HTTP ${res.status}).`,
      };
    }
    return { scanId: data.scanId, repositoryId: data.repositoryId, status: data.status, uploadType: data.uploadType, originalFileName: data.originalFileName };
  } catch {
    return { error: `Backend returned an invalid response (HTTP ${res.status}).` };
  }
}

export async function fetchScanStatus(
  repositoryId: string,
  scanId: string,
  signal?: AbortSignal
): Promise<ScanStatusPayload | null> {
  return safeGet<ScanStatusPayload>(
    `${BACKEND_URL}/api/repositories/${encodeURIComponent(repositoryId)}/scan/${encodeURIComponent(scanId)}/status`,
    signal
  );
}

export async function fetchScanFindings(
  repositoryId: string,
  scanId: string,
  signal?: AbortSignal
): Promise<FindingsPayload | null> {
  return safeGet<FindingsPayload>(
    `${BACKEND_URL}/api/repositories/${encodeURIComponent(repositoryId)}/scan/${encodeURIComponent(scanId)}/findings`,
    signal
  );
}

export async function fetchScanPatches(
  repositoryId: string,
  scanId: string,
  signal?: AbortSignal
): Promise<PatchRecord[]> {
  const payload = await safeGet<{ patches?: Record<string, unknown> }>(
    `${BACKEND_URL}/api/repositories/${encodeURIComponent(repositoryId)}/scan/${encodeURIComponent(scanId)}/patches`,
    signal
  );
  const patches = payload?.patches;
  if (!patches || typeof patches !== 'object') return [];
  const out: PatchRecord[] = [];
  for (const [vulnerability_id, entry] of Object.entries(patches)) {
    const rec = (entry ?? {}) as { candidates?: PatchCandidate[] };
    const candidates = Array.isArray(rec.candidates) ? rec.candidates : [];
    if (candidates.length === 0) {
      out.push({ vulnerability_id, ...(rec as PatchRecord) });
      continue;
    }
    for (const c of candidates) {
      out.push({ vulnerability_id, ...c });
    }
  }
  return out;
}