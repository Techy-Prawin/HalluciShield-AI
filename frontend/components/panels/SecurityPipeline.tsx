'use client';

import React from 'react';
import styles from './panels.module.css';
import { GlassPanel, SparkWave } from '@/components/hud/hud';
import { Icon, type IconName } from '@/components/icons';
import { useOptionalCommandCenter } from '@/components/command/CommandCenterContext';
import { cx } from '@/lib/hud';
import type { ScanStatusPayload, ScanStages } from '@/lib/api';

interface StageDef {
  key: keyof ScanStages;
  label: string;
  icon: IconName;
  color: string;
}

/** The ten pipeline stages owned and reported by the backend. */
const PIPELINE: StageDef[] = [
  { key: 'repository', label: 'Repository', icon: 'folder', color: 'var(--green)' },
  { key: 'analysis', label: 'Analysis', icon: 'code', color: 'var(--cyan)' },
  { key: 'hallucination', label: 'Hallucination Detection', icon: 'eye', color: 'var(--magenta)' },
  { key: 'dependency', label: 'Dependency Analysis', icon: 'box', color: 'var(--sky)' },
  { key: 'security', label: 'Security Scan', icon: 'shield', color: 'var(--red)' },
  { key: 'risk', label: 'Risk Assessment', icon: 'gauge', color: 'var(--amber)' },
  { key: 'patch', label: 'Patch Generation', icon: 'wrench', color: 'var(--teal)' },
  { key: 'validation', label: 'Validation', icon: 'check', color: 'var(--blue)' },
  { key: 'confidence', label: 'Confidence', icon: 'target', color: 'var(--violet)' },
  { key: 'runtime', label: 'Runtime', icon: 'pulse', color: 'var(--lime)' },
];

const SETTLED = ['COMPLETED', 'FAILED', 'SKIPPED', 'NOT_APPLICABLE'];

interface StageView {
  state: string;
  durationMs?: number;
  error?: string;
  color: string;
  node: 'done' | 'active' | 'idle' | 'na' | 'failed';
}

/** Map a backend stage state to visual + text, without inventing progress. */
function stageView(def: StageDef, stage: { state?: string; durationMs?: number; error?: string } | undefined): StageView {
  const s = stage?.state;
  if (!s) {
    return { state: 'PENDING', durationMs: stage?.durationMs, color: 'var(--text-3)', node: 'idle' };
  }
  switch (s) {
    case 'COMPLETED':
    case 'SUCCESS':
      return { state: s, durationMs: stage?.durationMs, color: 'var(--green)', node: 'done' };
    case 'RUNNING':
      return { state: s, durationMs: stage?.durationMs, color: 'var(--cyan)', node: 'active' };
    case 'FAILED':
      return { state: s, durationMs: stage?.durationMs, error: stage?.error, color: 'var(--red)', node: 'failed' };
    case 'SKIPPED':
      return { state: s, durationMs: stage?.durationMs, color: 'var(--amber)', node: 'na' };
    case 'NOT_APPLICABLE':
      return { state: s, durationMs: stage?.durationMs, color: 'var(--text-3)', node: 'na' };
    case 'QUEUED':
      return { state: s, durationMs: stage?.durationMs, color: 'var(--text-2)', node: 'idle' };
    default:
      return { state: s, durationMs: stage?.durationMs, color: 'var(--text-2)', node: 'idle' };
  }
}

export function SecurityPipeline({ className }: { className?: string }) {
  const ctx = useOptionalCommandCenter();
  const scan = ctx?.scan ?? null;

  const views = PIPELINE.map((def) => ({
    def,
    view: stageView(def, scan?.stages?.[def.key] as { state?: string; durationMs?: number; error?: string } | undefined),
  }));

  const settledCount = views.filter((v) => SETTLED.includes(v.view.state)).length;
  const activeCount = views.filter((v) => v.view.state === 'RUNNING').length;
  const failedStages = views.filter((v) => v.view.state === 'FAILED');
  const scanLabel = scan ? (scan.status ?? 'IDLE') : 'IDLE';

  return (
    <GlassPanel title="Security Pipeline" icon="route" live liveLabel="Scan" accent="green" className={className}>
      <div className={styles.pipeWrap}>
        {views.map(({ def, view }, i) => (
          <div className={styles.pipeStage} key={def.key}>
            <div className={styles.pipeNodeWrap}>
              {i > 0 && <span className={cx(styles.pipeLink, views[i - 1].view.node === 'done' && styles.pipeLinkDone)} />}
              <span
                className={cx(
                  styles.pipeNode,
                  view.node === 'done' && styles.pipeNodeDone,
                  view.node === 'active' && styles.pipeNodeActive,
                  view.node === 'idle' && styles.pipeNodeIdle
                )}
                style={{ borderColor: view.state === 'RUNNING' ? view.color : undefined }}
                title={`${def.label}: ${view.state}`}
              >
                <Icon name={def.icon} size={15} />
              </span>
            </div>
            <span className={styles.pipeName}>{def.label}</span>
            <span className={styles.pipePct} style={{ color: view.color }}>
              {view.state === 'NOT_APPLICABLE' ? 'N/A' : view.state.replace(/_/g, ' ')}
            </span>
            {view.error && (
              <span className={styles.pipeStatus} style={{ color: 'var(--red)', maxWidth: 130 }}>
                <Icon name="alert" size={9} /> {view.error}
              </span>
            )}
          </div>
        ))}
      </div>

      <div className={styles.pipeStats}>
        <span className={styles.monoValue}>
          SCAN STATE: <b>{scanLabel}</b>
        </span>
        <span className={styles.monoValue}>
          {settledCount}/{PIPELINE.length} STAGES RESOLVED · {activeCount} RUNNING
        </span>
        {failedStages.length > 0 && (
          <span className={styles.monoValue} style={{ color: 'var(--red)' }}>
            {failedStages.length} STAGE{failedStages.length > 1 ? 'S' : ''} FAILED
          </span>
        )}
      </div>

      <SparkWave color={activeCount > 0 ? 'var(--cyan)' : 'var(--green)'} height={36} />
    </GlassPanel>
  );
}