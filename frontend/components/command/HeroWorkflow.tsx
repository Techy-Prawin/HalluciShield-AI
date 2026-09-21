'use client';

import React from 'react';
import Link from 'next/link';
import styles from './heroWorkflow.module.css';
import { StatusDot } from '@/components/hud/hud';
import { Icon, type IconName } from '@/components/icons';
import { useCommandCenter } from './CommandCenterContext';
import { cx, threatLevel, timeAgo } from '@/lib/hud';
import { UploadPortal } from '@/app/components/UploadPortal';
import { extractFindings, totalVulnerabilities, type ScanStages, type ScanStatusPayload } from '@/lib/api';

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

              {(scan.hasOutputFile || scan.downloadUrl) && scan.status === 'COMPLETED' && (
                <button
                  className={cx(styles.heroBtn, styles.heroBtnPrimary)}
                  onClick={requestDownload}
                  disabled={ctx.downloadState.busy}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '8px',
                    width: '100%',
                    padding: '10px 16px',
                    backgroundColor: 'var(--green)',
                    color: '#0a0d14',
                    fontWeight: 700,
                    borderRadius: '6px',
                    textDecoration: 'none',
                    letterSpacing: '0.05em',
                    cursor: ctx.downloadState.busy ? 'wait' : 'pointer',
                    opacity: ctx.downloadState.busy ? 0.7 : 1,
                  }}
                  title={ctx.downloadState.busy ? 'Downloading…' : 'Download the secured output file'}
                >
                  <Icon name={ctx.downloadState.busy ? 'refresh' : 'download'} size={16} />
                  {ctx.downloadState.busy
                    ? 'DOWNLOADING…'
                    : `DOWNLOAD SECURED ${scan.uploadType === 'single_file' ? 'FILE' : 'REPOSITORY'}`}
                </button>
              )}

              {ctx.downloadState.error && (
                <div className={styles.consoleError}>
                  <Icon name="alert" size={14} /> {ctx.downloadState.error}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </section>
  );
}

function findStageState(scan: ScanStatusPayload | null, key: keyof ScanStages): string {
  return scan?.stages?.[key]?.state ?? 'PENDING';
}

function ScanSummary({ scan, secureCode }: { scan: ScanStatusPayload; secureCode: boolean }) {
  const applied = scan.remediation?.patchesAppliedCount ?? null;
  const securityChanges =
    secureCode
      ? 'None Required'
      : scan.remediation && (scan.remediation.patchesAppliedCount ?? 0) > 0
        ? `${scan.remediation.patchesAppliedCount} Applied`
        : applied === 0
          ? 'None Required'
          : 'Pending';

  const verification =
    scan.remediation?.rescanned === true
      ? `${scan.remediation.afterFindingsCount ?? 0} findings after re-scan · risk ${scan.remediation.afterRiskScore ?? 0}/100`
      : scan.status === 'COMPLETED'
        ? 'Verification complete'
        : 'Not verified';

  return (
    <div className={styles.scanSummary}>
      <span className={styles.findingsTitle}>SCAN SUMMARY</span>
      <div className={styles.summaryGrid}>
        <SummaryCell label="RISK" value={typeof scan.riskScore === 'number' ? `${scan.riskScore}/100 (${scan.riskLevel || 'N/A'})` : 'N/A'} color={riskColor(scan.riskScore)} />
        <SummaryCell label="CONFIDENCE" value={typeof scan.confidence === 'number' ? `${scan.confidence}%` : 'N/A'} color="var(--violet)" />
        <SummaryCell label="SECURITY CHANGES" value={securityChanges} color="var(--green)" />
        <SummaryCell label="FINAL VERIFICATION" value={verification} color="var(--sky)" />
        <SummaryCell label="SECURED OUTPUT" value={scan.hasOutputFile ? 'Available' : 'Unavailable'} color={scan.hasOutputFile ? 'var(--green)' : 'var(--amber)'} />
        <SummaryCell label="STATUS" value={scan.status ?? '—'} color={statusColor(scan.status)} />
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