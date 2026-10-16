'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import styles from './heroWorkflow.module.css';
import { StatusDot } from '@/components/hud/hud';
import { Icon, type IconName } from '@/components/icons';
import { useCommandCenter } from './CommandCenterContext';
import { cx, threatLevel, timeAgo } from '@/lib/hud';
import { UploadPortal } from '@/app/components/UploadPortal';
import {
  extractFindings,
  totalVulnerabilities,
  acknowledgeUnverifiedDownload,
  downloadSecuredFile,
  type DownloadEligibility,
  type ScanStages,
  type ScanStatusPayload,
} from '@/lib/api';

/* ------------------------------------------------------------------ */
/* WelcomeHero — command center masthead                              */
/* ------------------------------------------------------------------ */

function HeroChip({ label, value, color, dot }: { label: string; value: string; color: string; dot?: string }) {
  return (
    <div className={styles.heroChip}>
      {dot && <StatusDot color={dot} size={6} />}
      <span className={styles.heroChipLabel}>{label}</span>
      <span className={styles.heroChipValue} style={{ color }}>
        {value}
      </span>
    </div>
  );
}

export function WelcomeHero() {
  const ctx = useCommandCenter();
  const th = threatLevel(ctx.monitoring);

  return (
    <section className={styles.heroBlock}>
      <div className={styles.heroMain}>
        <div className={styles.heroBadgeWrap}>
          <span className={styles.heroBadge}>
            <StatusDot color="var(--green)" size={6} />
            HALLUCISHIELD AI · AUTONOMOUS SECURITY FABRIC
          </span>
          <span className={styles.heroVersion}>v2.4.0-PROD</span>
        </div>
        <h1 className={styles.heroTitle}>
          SECURE CODE <span className={styles.heroTitleDim}>AT AGENT SPEED</span>
        </h1>
        <p className={styles.heroLead}>
          Real-time multi-agent defense inspecting hallucinated dependencies, secret leaks, and critical code vulnerabilities before deployment.
        </p>
        <div className={styles.heroActions}>
          <a
            href="#scan-workflow"
            className={cx(styles.heroBtn, styles.heroBtnPrimary)}
            onClick={(e) => {
              e.preventDefault();
              document.getElementById('scan-workflow')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }}
          >
            <Icon name="scan" size={15} />
            START SECURITY SCAN
          </a>
          <Link href="/system" className={cx(styles.heroBtn, styles.heroBtnGhost)}>
            <Icon name="route" size={15} />
            EXPLORE SECURITY FABRIC
          </Link>
        </div>
      </div>

      <div className={styles.heroTelemetry}>
        <div className={styles.heroTelemetryHeader}>
          <span className={styles.heroTtl}>LIVE TELEMETRY</span>
          <span className={styles.heroSync}>SYNC {ctx.lastSync ? timeAgo(ctx.lastSync) : '…'}</span>
        </div>
        <div className={styles.heroChips}>
          <HeroChip label="SYSTEM" value={ctx.backendHealth?.status === 'ok' ? 'ONLINE' : 'OFFLINE'} color={ctx.backendHealth?.status === 'ok' ? 'var(--green)' : 'var(--red)'} dot={ctx.backendHealth?.status === 'ok' ? 'var(--green)' : 'var(--red)'} />
          <HeroChip label="AI CORE" value={ctx.aiHealth?.status === 'ok' ? 'ACTIVE' : 'IDLE'} color={ctx.aiHealth?.status === 'ok' ? 'var(--cyan)' : 'var(--amber)'} dot={ctx.aiHealth?.status === 'ok' ? 'var(--cyan)' : 'var(--amber)'} />
          <HeroChip label="THREAT LEVEL" value={th.label.toUpperCase()} color={th.color} dot={th.color} />
          <HeroChip label="PIPELINE" value="MULTI-AGENT" color="var(--blue)" />
          <HeroChip label="EVENTS" value={String(ctx.monitoring?.total_events ?? 0)} color="var(--text-1)" />
          <HeroChip label="ALERTS" value={String(ctx.monitoring?.total_alerts ?? 0)} color={ctx.monitoring?.total_alerts ? 'var(--amber)' : 'var(--green)'} />
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* ScanWorkflow — real ingest + scan orchestration                    */
/* ------------------------------------------------------------------ */

const STAGE_ORDER: Array<{ key: keyof ScanStages; label: string; color: string }> = [
  { key: 'repository', label: 'REPOSITORY', color: 'var(--green)' },
  { key: 'analysis', label: 'ANALYSIS', color: 'var(--cyan)' },
  { key: 'hallucination', label: 'HALLUCINATION', color: 'var(--magenta)' },
  { key: 'dependency', label: 'DEPENDENCY', color: 'var(--sky)' },
  { key: 'security', label: 'SECURITY', color: 'var(--red)' },
  { key: 'risk', label: 'RISK ASSESSMENT', color: 'var(--amber)' },
  { key: 'patch', label: 'PATCH REMEDIATION', color: 'var(--teal)' },
  { key: 'validation', label: 'VALIDATION', color: 'var(--blue)' },
  { key: 'confidence', label: 'CONFIDENCE', color: 'var(--violet)' },
  { key: 'runtime', label: 'RUNTIME', color: 'var(--lime)' },
];

export function ScanWorkflow() {
  const ctx = useCommandCenter();
  const scan = ctx.scan;
  const findings = ctx.findings;

  const hallucinationCount = findings ? extractFindings(findings.hallucinationFindings).length : null;
  const securityCount = findings ? extractFindings(findings.securityFindings).length : null;
  const dependencyCount = findings ? extractFindings(findings.dependencyFindings).length : null;
  const vulnTotalValid = findings ? totalVulnerabilities(findings.securityFindings) : null;

  const terminal = scan?.status === 'COMPLETED' || scan?.status === 'FAILED';
  const secureCode =
    terminal &&
    scan?.status === 'COMPLETED' &&
    scan.artifactAuthorization === 'AUTHORIZED' &&
    (vulnTotalValid === 0) &&
    findStageState(scan, 'patch') === 'NOT_APPLICABLE';

  const requestDownload = () => {
    if (!scan?.repositoryId || !scan?.scanId) return;
    void ctx.downloadSecuredFile(scan.repositoryId, scan.scanId);
  };

  return (
    <section id="scan-workflow" className={styles.scanBlock}>
      <div className={styles.scanHead}>
        <div className={styles.scanHeadLeft}>
          <span className={styles.scanHeadIcon}>
            <Icon name="upload" size={15} />
          </span>
          <div>
            <h2 className={styles.scanHeadTitle}>SECURE REPOSITORY INGESTION</h2>
            <p className={styles.scanHeadSub}>
              Upload a source file or .zip archive — zip-slip protected on ingest, then run through the multi-agent security pipeline owned entirely by the backend.
            </p>
          </div>
        </div>
        <span className={cx(styles.scanStatus, (scan?.status === 'COMPLETED' || scan?.status === 'FAILED') && styles.scanStatusIdle)}>
          <span className={styles.scanStatusDot} />
          {scanPollingLabel(scan?.status, ctx.scanPolling)}
        </span>
      </div>

      <div className={styles.scanGrid}>
        <div className={styles.scanUpload}>
          <UploadPortal
            scanError={ctx.scanError}
            scanning={ctx.scanPolling}
            onScanRequested={(repoId) => {
              void ctx.startScanFlow(repoId);
            }}
          />
        </div>

        <div className={styles.scanConsole}>
          {!scan ? (
            <div className={styles.consoleIdle}>
              <div className={styles.consoleIdleIcon}>
                <Icon name="route" size={22} />
              </div>
              <span>NO ACTIVE SCAN</span>
              <p>
                Ingest a repository to begin. The backend-owned security pipeline will materialize here with live stage telemetry.
              </p>
            </div>
          ) : (
            <>
              <div className={styles.consoleRow}>
                <span className={styles.consoleLabel}>REPOSITORY</span>
                <span className={styles.consoleValue} title={scan.repositoryId}>
                  {scan.repositoryId ?? '—'}
                </span>
                <Icon name="box" size={13} style={{ color: 'var(--cyan)' }} />
              </div>
              <div className={styles.consoleRow}>
                <span className={styles.consoleLabel}>SCAN ID</span>
                <span className={styles.consoleValue} title={scan.scanId}>
                  {scan.scanId ?? '—'}
                </span>
                <Icon name="scan" size={13} style={{ color: 'var(--cyan)' }} />
              </div>
              <div className={styles.consoleRow}>
                <span className={styles.consoleLabel}>STATUS</span>
                <span className={cx(styles.consoleValue, styles.consoleStatus)} style={{ color: statusColor(scan.status) }}>
                  {scan.status ?? '—'}
                </span>
                {ctx.scanPolling && <StatusDot color="var(--cyan)" size={7} />}
              </div>

              <div className={styles.stageList}>
                {STAGE_ORDER.map((s) => {
                  const stage = scan.stages?.[s.key];
                  const state = stage?.state ?? 'QUEUED';
                  return (
                    <div className={styles.stageRow} key={s.key}>
                      <span className={styles.stageDot} style={{ borderColor: s.color, boxShadow: state === 'RUNNING' ? `0 0 10px ${s.color}` : undefined }} />
                      <span className={styles.stageName} style={{ color: state === 'RUNNING' ? s.color : 'var(--text-2)' }}>
                        {s.label}
                      </span>
                      <span className={styles.stageState} style={{ color: stageStateColor(state) }}>
                        {state.replace(/_/g, ' ')}
                        {stage?.durationMs ? ` · ${Math.round(stage.durationMs / 1000)}s` : ''}
                      </span>
                    </div>
                  );
                })}
              </div>

              {scan.stages?.securedFile && findStageState(scan, 'securedFile') !== 'NOT_APPLICABLE' && (
                <div className={styles.consoleRow}>
                  <span className={styles.consoleLabel}>SECURED OUTPUT</span>
                  <span className={styles.consoleValue} title={scan.securedFileName ?? scan.outputFile ?? '—'}>
                    {scan.securedFileName ?? scan.outputFile ?? '—'}
                  </span>
                  <Icon name="lock" size={13} style={{ color: 'var(--green)' }} />
                </div>
              )}

              {scan.error && (
                <div className={styles.consoleError}>
                  <Icon name="alert" size={14} /> {scan.error}
                </div>
              )}

              {findings && (
                <div className={styles.findingsBlock}>
                  <span className={styles.findingsTitle}>FINDINGS SUMMARY</span>
                  <div className={styles.findingsRow}>
                    <FindingCount label="HALLUCINATION" value={hallucinationCount} color="var(--magenta)" />
                    <FindingCount label="SECURITY" value={securityCount} color="var(--red)" />
                    <FindingCount label="DEPENDENCY" value={dependencyCount} color="var(--sky)" />
                  </div>
                </div>
              )}

              {terminal && (
                <ScanSummary scan={scan} secureCode={secureCode === true} />
              )}

              {secureCode === true && (
                <div className={styles.secureBanner}>
                  <span className={styles.secureBannerIcon}>
                    <Icon name="check" size={14} />
                  </span>
                  <div className={styles.secureBannerBody}>
                    <b>SECURE CODE VERIFIED</b>
                    <span>No security changes were required — the secured output may be identical to the original file.</span>
                  </div>
                </div>
              )}

              {scan.status === 'COMPLETED' && (scan.downloadUrl || scan.downloadEligibility?.level === 'INELIGIBLE' || scan.artifactAuthorization === 'BLOCKED') && <DownloadControl scan={scan} />}

              {ctx.downloadState.error && (
                <div className={styles.consoleError}>
                  <Icon name="alert" size={14} /> {ctx.downloadState.error}
                </div>
              )}
              {ctx.acknowledgementState.error && (
                <div className={styles.consoleError}>
                  <Icon name="alert" size={14} /> {ctx.acknowledgementState.error}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </section>
  );
}

function DownloadControl({ scan }: { scan: ScanStatusPayload }) {
  const ctx = useCommandCenter();
  const elig: DownloadEligibility | null = scan.downloadEligibility ?? null;
  const verdict = scan.securityVerdict ?? 'PENDING';
  const auth = scan.artifactAuthorization ?? 'PENDING';
  const [locallyAcknowledged, setLocallyAcknowledged] = useState(false);

  const eligible = elig?.eligible === true;
  const needsAck = elig?.acknowledgementRequired === true;
  const ace = elig?.aceScore;

  const handleDownload = async () => {
    if (!scan.repositoryId || !scan.scanId) return;
    if (needsAck && !locallyAcknowledged) return;
    await ctx.downloadSecuredFile(scan.repositoryId, scan.scanId, needsAck);
  };

  const handleAcknowledgeAndDownload = async () => {
    if (!scan.repositoryId || !scan.scanId) return;
    const result = await ctx.acknowledgeDownload(scan.repositoryId, scan.scanId);
    if (result.ok) setLocallyAcknowledged(true);
    else return;
    await ctx.downloadSecuredFile(scan.repositoryId, scan.scanId, true);
  };

  const rowColor = verdict === 'PASSED' ? 'var(--green)' : verdict === 'BLOCKED' ? 'var(--red)' : 'var(--amber)';
  const metaRows = [
    { label: 'ACE SCORE', value: typeof ace === 'number' ? `${ace} / 100` : 'NOT AVAILABLE', note: 'scale 0-100 — score never fabricated' },
    { label: 'VALIDATION', value: String(scan.stages?.validation?.state ?? '—'), note: scan.stages?.validation?.details?.unverifiedResults != null ? `unverified results: ${scan.stages.validation.details.unverifiedResults}` : undefined },
    { label: 'SECURITY VERDICT', value: String(verdict).toUpperCase(), note: 'independent of download eligibility' },
    { label: 'DOWNLOAD ELIGIBILITY', value: String(elig?.level ?? '—').toUpperCase(), note: elig?.reason ?? undefined },
  ];

  const inline: {
    control: React.CSSProperties;
    meta: React.CSSProperties;
    metaRow: React.CSSProperties;
    metaLabel: React.CSSProperties;
    metaValue: React.CSSProperties;
    metaNote: React.CSSProperties;
    banner: (color: string) => React.CSSProperties;
    reason: React.CSSProperties;
    actions: React.CSSProperties;
    ackLabel: React.CSSProperties;
    ackActions: React.CSSProperties;
  } = {
    control: { border: '1px solid var(--border)', borderRadius: '8px', padding: '12px 14px', marginTop: '10px', background: 'var(--panel)' },
    meta: { display: 'flex', flexDirection: 'column', gap: '6px' },
    metaRow: { display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: '8px' },
    metaLabel: { fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-3)' },
    metaValue: { fontSize: '13px', fontWeight: 700, color: 'var(--text-1)' },
    metaNote: { fontSize: '10.5px', color: 'var(--text-3)' },
    banner: (color: string) => ({ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 10px', borderRadius: '6px', background: color === 'var(--red)' ? 'rgba(239,68,68,0.12)' : 'rgba(245,158,11,0.12)', border: `1px solid ${color}`, marginTop: '10px' }),
    reason: { fontSize: '12px', color: 'var(--text-2)', marginTop: '8px' },
    actions: { display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '10px' },
    ackLabel: { display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12.5px', color: 'var(--text-1)', cursor: 'pointer' },
    ackActions: { display: 'flex', gap: '8px' },
  };

  const buttonStyle = (color: string): React.CSSProperties => ({
    display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '8px', width: '100%', padding: '10px 14px',
    backgroundColor: color, color: '#0a0d14', fontWeight: 700, borderRadius: '6px', textDecoration: 'none', letterSpacing: '0.05em',
    border: 'none', cursor: 'pointer', fontSize: '12.5px',
  });

  return (
    <div className={styles.downloadControl} style={inline.control}>
      <div style={inline.meta}>
        {metaRows.map((row) => (
          <div key={row.label} style={inline.metaRow}>
            <span style={inline.metaLabel}>{row.label}</span>
            <span style={{ ...inline.metaValue, color: row.label === 'SECURITY VERDICT' ? rowColor : 'var(--text-1)' }}>{row.value}</span>
            {row.note && <span style={inline.metaNote}>{row.note}</span>}
          </div>
        ))}
      </div>

      {auth === 'BLOCKED' || elig?.level === 'INELIGIBLE' ? (
        <div style={inline.banner('var(--red)')}>
          <Icon name="alert" size={14} style={{ color: 'var(--red)' }} />
          <span style={{ fontSize: '12.5px', fontWeight: 700, color: 'var(--red)' }}>DOWNLOAD BLOCKED — {elig?.reason ?? 'This candidate is not eligible for download.'}</span>
        </div>
      ) : (
        <>
          {verdict !== 'PASSED' && (
            <div style={inline.banner('var(--amber)')}>
              <Icon name="alert" size={14} style={{ color: 'var(--amber)' }} />
              <span style={{ fontSize: '12.5px', fontWeight: 700, color: 'var(--amber)' }}>
                UNVERIFIED — USE AT YOUR OWN RISK. This candidate has not passed security verification and may contain unresolved issues.
              </span>
            </div>
          )}
          <div style={inline.actions}>
            {!needsAck && (
              <button
                className={cx(styles.heroBtn, styles.heroBtnPrimary)}
                onClick={handleDownload}
                disabled={ctx.downloadState.busy || !eligible}
                style={buttonStyle('var(--green)')}
              >
                <Icon name={ctx.downloadState.busy ? 'refresh' : 'download'} size={16} />
                {ctx.downloadState.busy ? 'DOWNLOADING…' : `DOWNLOAD ${auth === 'AUTHORIZED' ? 'SECURED CODE' : 'UNVERIFIED CODE'}`}
              </button>
            )}
            {needsAck && (
              <>
                <label style={inline.ackLabel}>
                  <input
                    type="checkbox"
                    checked={locallyAcknowledged}
                    onChange={(e) => setLocallyAcknowledged(e.target.checked)}
                    disabled={ctx.acknowledgementState.busy}
                    style={downloadInputStyle()}
                  />
                  <span>I understand this code is UNVERIFIED and may contain unresolved security issues. I accept the risk.</span>
                </label>
                <div style={inline.ackActions}>
                  {locallyAcknowledged ? (
                    <button
                      className={cx(styles.heroBtn, styles.heroBtnPrimary)}
                      onClick={handleDownload}
                      disabled={ctx.downloadState.busy || !eligible}
                      style={buttonStyle('var(--green)')}
                    >
                      {ctx.downloadState.busy ? 'DOWNLOADING…' : 'DOWNLOAD UNVERIFIED CODE'}
                    </button>
                  ) : (
                    <button
                      className={cx(styles.heroBtn, styles.heroBtnPrimary)}
                      onClick={handleAcknowledgeAndDownload}
                      disabled={ctx.acknowledgementState.busy || !eligible}
                      style={buttonStyle('var(--amber)')}
                    >
                      {ctx.acknowledgementState.busy ? 'ACKNOWLEDGING…' : 'ACKNOWLEDGE RISK &amp; DOWNLOAD'}
                    </button>
                  )}
                </div>
              </>
            )}
          </div>
              </>
            )}
            {!eligible && auth !== 'BLOCKED' && (
        <p style={inline.reason}>{elig?.reason ?? 'Download eligibility could not be determined.'}</p>
      )}
    </div>
  );
}

function downloadInputStyle() {
  return { width: '16px', height: '16px', cursor: 'pointer', accentColor: 'var(--amber)' };
}


function findStageState(scan: ScanStatusPayload | null, key: keyof ScanStages): string {
  return scan?.stages?.[key]?.state ?? 'PENDING';
}

function ScanSummary({ scan, secureCode }: { scan: ScanStatusPayload; secureCode: boolean }) {
  const aceScore = scan.downloadEligibility?.aceScore ?? scan.confidence;
  const applied = scan.remediation?.patchesAppliedCount ?? null;
  const residualFindings = scan.remediation?.afterFindingsCount ?? 0;
  const securityChanges =
    secureCode
      ? 'None Required'
      : residualFindings > 0
        ? 'Blocked · residual findings'
      : scan.remediation && (scan.remediation.patchesAppliedCount ?? 0) > 0
        ? `${scan.remediation.patchesAppliedCount} Applied`
        : applied === 0
          ? 'None Required'
          : 'Pending';

  const verification =
    scan.remediation?.rescanned === true
      ? `${scan.remediation.afterFindingsCount ?? 0} findings after re-scan · risk ${scan.remediation.afterRiskScore ?? 0}/100`
      : scan.stages?.securedFile?.state === 'FAILED' || scan.stages?.securedFile?.state === 'SKIPPED'
        ? 'Blocked · not verified'
        : 'Not verified';

  const elig = scan.downloadEligibility;
  const verdictColor = (v: string) => (v === 'PASSED' ? 'var(--green)' : v === 'BLOCKED' ? 'var(--red)' : 'var(--amber)');

  return (
    <div className={styles.scanSummary}>
      <span className={styles.findingsTitle}>SCAN SUMMARY</span>
      <div className={styles.summaryGrid}>
        <SummaryCell label="RISK" value={typeof scan.riskScore === 'number' ? `${scan.riskScore}/100 (${scan.riskLevel || 'N/A'})` : 'N/A'} color={riskColor(scan.riskScore)} />
        <SummaryCell label="CONFIDENCE" value={typeof aceScore === 'number' ? `ACE ${aceScore}/100` : `ACE N/A`} color="var(--violet)" />
        <SummaryCell label="SECURITY VERDICT" value={String(scan.securityVerdict ?? '—').toUpperCase()} color={verdictColor(String(scan.securityVerdict ?? ''))} />
        <SummaryCell label="SECURITY CHANGES" value={securityChanges} color="var(--green)" />
        <SummaryCell label="FINAL VERIFICATION" value={verification} color="var(--sky)" />
        <SummaryCell label="SECURED OUTPUT" value={scan.hasOutputFile ? 'Available' : 'Unavailable'} color={scan.hasOutputFile ? 'var(--green)' : 'var(--amber)'} />
        <SummaryCell label="SCAN" value={scan.status ?? '—'} color={statusColor(scan.status)} />
        <SummaryCell
          label="ARTIFACT AUTHORIZATION"
          value={String(scan.artifactAuthorization ?? 'PENDING').toUpperCase()}
          color={scan.artifactAuthorization === 'AUTHORIZED' ? 'var(--green)' : scan.artifactAuthorization === 'BLOCKED' ? 'var(--red)' : 'var(--amber)'}
        />
        <SummaryCell
          label="DOWNLOAD ELIGIBILITY"
          value={String(elig?.level ?? '—').toUpperCase()}
          color={elig?.level === 'AUTHORIZED' ? 'var(--green)' : elig?.level === 'INELIGIBLE' ? 'var(--red)' : 'var(--amber)'}
        />
      </div>
    </div>
  );
}

function SummaryCell({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className={styles.summaryCell}>
      <span className={styles.summaryCellLabel}>{label}</span>
      <span className={styles.summaryCellValue} style={{ color }}>
        {value}
      </span>
    </div>
  );
}

function scanPollingLabel(status?: string, polling?: boolean): string {
  if (!status) return 'STANDBY';
  if (status === 'COMPLETED') return 'SCAN COMPLETE';
  if (status === 'FAILED') return 'SCAN FAILED';
  return polling ? 'SCANNING…' : 'QUEUED';
}

function statusColor(status?: string): string {
  if (status === 'COMPLETED' || status === 'SUCCESS') return 'var(--green)';
  if (status === 'FAILED') return 'var(--red)';
  if (status === 'RUNNING') return 'var(--cyan)';
  return 'var(--amber)';
}

function stageStateColor(state: string): string {
  if (state === 'COMPLETED' || state === 'SUCCESS') return 'var(--green)';
  if (state === 'FAILED') return 'var(--red)';
  if (state === 'RUNNING') return 'var(--cyan)';
  if (state === 'NOT_APPLICABLE' || state === 'SKIPPED') return 'var(--text-3)';
  return 'var(--text-2)';
}

function riskColor(score: number | null | undefined): string {
  if (typeof score !== 'number') return 'var(--text-3)';
  if (score > 70) return 'var(--red)';
  if (score > 40) return 'var(--amber)';
  return 'var(--green)';
}

function FindingCount({ label, value, color }: { label: string; value: number | null; color: string }) {
  return (
    <div className={styles.findingCount}>
      <span className={styles.findingCountValue} style={{ color }}>
        {value === null ? '—' : String(value)}
      </span>
      <span className={styles.findingCountLabel}>{label}</span>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* PageHeader — masthead for sub-route pages                          */
/* ------------------------------------------------------------------ */

interface PageHeaderProps {
  eyebrow: string;
  title: string;
  icon: IconName;
  children?: React.ReactNode;
}

export function PageHeader({ eyebrow, title, icon, children }: PageHeaderProps) {
  return (
    <header className={styles.pageHead}>
      <div className={styles.pageHeadIcon}>
        <Icon name={icon} size={18} />
      </div>
      <div className={styles.pageHeadCopy}>
        <span className={styles.pageEyebrow}>{eyebrow}</span>
        <h1 className={styles.pageTitle}>{title}</h1>
        {children && <span className={styles.pageSub}>{children}</span>}
      </div>
      <div className={styles.pageHeadRight}>
        <span className={styles.pageAsset}>SECTOR 7 · VULNMATRIX</span>
      </div>
    </header>
  );
}
