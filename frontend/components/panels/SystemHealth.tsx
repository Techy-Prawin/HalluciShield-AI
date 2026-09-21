'use client';

import React from 'react';
import styles from './panels.module.css';
import { GlassPanel, StatusDot, RingGauge } from '@/components/hud/hud';
import { Icon, type IconName } from '@/components/icons';
import { useOptionalCommandCenter } from '@/components/command/CommandCenterContext';
import { fmtUptime, cx } from '@/lib/hud';

interface ServiceRow {
  key: string;
  name: string;
  icon: IconName;
}

export function SystemHealth({ className }: { className?: string }) {
  const ctx = useOptionalCommandCenter();
  const backendOk = ctx?.backendHealth?.status === 'ok';
  const aiOk = ctx?.aiHealth?.status === 'ok';
  const monitoringOk = ctx?.monitoring !== null;
  const learningOk = ctx?.learningSummary !== null;
  const connected = Number(backendOk) + Number(aiOk) + Number(monitoringOk) + Number(learningOk);
  const totalChecks = 4;
  const availability = Math.round((connected / totalChecks) * 1000) / 10;
  const uptimeSec = ctx?.monitoring?.uptime_seconds ?? null;
  const dbState = ctx?.backendHealth?.dependencies?.database;
  const rawSandbox = ctx?.scan?.stages?.validation?.details as Record<string, unknown> | undefined;
  const sandboxStatus = typeof rawSandbox?.sandboxStatus === 'string' ? rawSandbox.sandboxStatus : null;
  const sandboxState =
    ctx?.scan?.remediation?.sandboxVerified === true
      ? 'VERIFIED'
      : sandboxStatus ?? (ctx?.scan ? 'N/A' : 'INDIRECT');

  const services: Array<{ row: ServiceRow; on: boolean; state: string; color: string }> = [
    { row: { key: 'ai', name: 'AI Core', icon: 'cpu' }, on: aiOk, state: aiOk ? 'ONLINE' : 'OFFLINE', color: 'var(--cyan)' },
    { row: { key: 'db', name: 'Database', icon: 'db' }, on: dbState === 'connected', state: dbState === 'connected' ? 'CONNECTED' : dbState ? 'DEGRADED' : 'UNREACHED', color: dbState === 'connected' ? 'var(--green)' : 'var(--amber)' },
    { row: { key: 'backend', name: 'Backend', icon: 'server' }, on: backendOk, state: backendOk ? 'ONLINE' : 'OFFLINE', color: 'var(--cyan)' },
    { row: { key: 'frontend', name: 'Frontend', icon: 'layers' }, on: true, state: 'ONLINE', color: 'var(--green)' },
    { row: { key: 'agents', name: 'Agents', icon: 'box' }, on: aiOk, state: aiOk ? 'READY' : 'OFFLINE', color: 'var(--cyan)' },
    { row: { key: 'sandbox', name: 'Sandbox', icon: 'lock' }, on: sandboxState === 'VERIFIED', state: sandboxState, color: sandboxState === 'VERIFIED' ? 'var(--green)' : 'var(--amber)' },
  ];

  return (
    <GlassPanel title="System Health" icon="activity" live={!ctx?.isConnecting} liveLabel={ctx?.isConnecting ? 'Probing' : 'Telemetry'} accent="green" className={className}>
      <div className={styles.healthGrid}>
        {services.map((s) => (
          <div className={styles.healthRow} key={s.row.key}>
            <span className={styles.healthName}>
              <StatusDot color={s.color} size={7} />
              <Icon name={s.row.icon} size={13} style={{ color: s.color }} />
              {s.row.name}
            </span>
            <span className={styles.healthState} style={{ color: s.color }}>
              {s.state}
            </span>
          </div>
        ))}
      </div>

      <div className={styles.uptimeWrap}>
        <RingGauge value={availability} label="Service Availability" sublabel={`Live uptime: ${fmtUptime(uptimeSec)}`} size={132} color="var(--green)" />
        <span className={styles.uptimeMeta}>{connected}/{totalChecks} endpoints reporting · no SLA claim</span>
        <span className={styles.uptimeMeta}>
          {ctx?.backendHealth?.version ? `Backend v${ctx.backendHealth.version} · ` : ''}
          {ctx?.aiHealth?.version ? `AI Engine v${ctx.aiHealth.version}` : 'AI Engine version pending'}
        </span>
      </div>
    </GlassPanel>
  );
}

export function ActiveAgents({ className }: { className?: string }) {
  const ctx = useOptionalCommandCenter();
  const scan = ctx?.scan;

  interface AgentRow {
    id: string;
    name: string;
    icon: IconName;
    color: string;
  }

  const rows: AgentRow[] = [
    { id: 'hallucination', name: 'Hallucination Detection', icon: 'eye', color: 'var(--magenta)' },
    { id: 'security', name: 'Security Scanner', icon: 'shield', color: 'var(--red)' },
    { id: 'patch', name: 'Patch Generator', icon: 'wrench', color: 'var(--green)' },
    { id: 'validation', name: 'Validation Agent', icon: 'check', color: 'var(--cyan)' },
    { id: 'confidence', name: 'Confidence Engine', icon: 'target', color: 'var(--violet)' },
    { id: 'runtime', name: 'Runtime Monitoring', icon: 'pulse', color: 'var(--lime)' },
  ];

  const activityFor = (id: string): { label: string; active: boolean; color: string } => {
    if (!scan) return { label: 'Standing by — awaiting scan', active: false, color: 'var(--text-3)' };
    const stageMap = scan.stages as Record<string, { state?: string }> | undefined;
    const state = stageMap?.[id]?.state;
    if (state === 'RUNNING') return { label: 'Executing stage', active: true, color: 'var(--cyan)' };
    if (state === 'COMPLETED' || state === 'SUCCESS') return { label: 'Stage complete', active: false, color: 'var(--green)' };
    if (state === 'FAILED') return { label: 'Stage failed', active: false, color: 'var(--red)' };
    if (state === 'NOT_APPLICABLE' || state === 'SKIPPED') return { label: 'Not applicable', active: false, color: 'var(--text-3)' };
    if (state === 'QUEUED') return { label: 'Queued', active: false, color: 'var(--text-2)' };
    return { label: 'Standing by', active: false, color: 'var(--text-3)' };
  };

  return (
    <GlassPanel title="Active Agents" icon="layers" live accent="blue" className={className}>
      <div className={styles.agentsList}>
        {rows.map((a) => {
          const act = activityFor(a.id);
          return (
            <div className={styles.agentRow} key={a.id}>
              <span className={styles.agentIcon} style={{ color: a.color }}>
                <Icon name={a.icon} size={14} />
              </span>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
                <span className={styles.agentName}>{a.name}</span>
                <span className={styles.agentAct}>{act.label}</span>
              </div>
              <StatusDot color={act.active ? 'var(--cyan)' : act.color} size={8} pulse={act.active} />
            </div>
          );
        })}
      </div>
      <div className={cx(styles.row)}>
        <span className={styles.monoValue} style={{ fontSize: 9.5, color: 'var(--text-3)' }}>
          {ctx?.learningSummary?.model_version ? `Model v${ctx.learningSummary.model_version} · ` : ''}
          Multi-agent security pipeline{scan ? ` · ${scan.status ?? '—'}` : ''} · {ctx?.monitoring?.total_events ?? 0} events observed
        </span>
      </div>
    </GlassPanel>
  );
}