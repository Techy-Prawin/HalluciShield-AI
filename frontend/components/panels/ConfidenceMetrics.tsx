'use client';

import React from 'react';
import styles from './panels.module.css';
import { GlassPanel, RingGauge } from '@/components/hud/hud';
import { useOptionalCommandCenter } from '@/components/command/CommandCenterContext';
import { percent } from '@/lib/hud';

export function ConfidenceMetrics({ className }: { className?: string }) {
  const ctx = useOptionalCommandCenter();
  const liveRecords = ctx?.learningSummary?.total_records ?? null;
  const modelVersion = ctx?.learningSummary?.model_version ?? null;
  const acceptance = (ctx?.learningSummary?.overall_acceptance_rate ?? 0) * 100;
  const deployment = (ctx?.learningSummary?.overall_deployment_success ?? 0) * 100;
  const scanConfidence = typeof ctx?.scan?.confidence === 'number' ? ctx.scan.confidence : null;
  const features = [
    ...(scanConfidence !== null ? [{ label: 'Latest Scan Confidence', value: scanConfidence, real: true }] : []),
    { label: 'Developer Acceptance', value: acceptance, real: ctx?.learningSummary != null },
    { label: 'Deployment Success', value: deployment, real: ctx?.learningSummary != null },
  ];
  const overall = features.length > 0 ? features.reduce((sum, feature) => sum + feature.value, 0) / features.length : 0;

  return (
    <GlassPanel title="Confidence Metrics" icon="gauge" live={!!ctx} liveLabel={ctx ? 'Backend' : 'Offline'} accent="violet" className={className}>
      <div className={styles.confTop}>
        <RingGauge value={overall} label={scanConfidence !== null ? 'Scan Confidence' : 'Reported'} size={128} color="var(--violet)" />

        <div className={styles.confMeta}>
          <span>
            <b style={{ color: 'var(--cyan)' }}>Confidence</b> as reported by the backend pipeline
          </span>
          <span>Latest scan: {scanConfidence !== null ? `${scanConfidence}%` : 'no scan yet'}</span>
          <span>
            Live learning records: <b style={{ color: 'var(--text-0)' }}>{liveRecords ?? '—'}</b>
            {modelVersion ? ` · model ${modelVersion}` : ''}
          </span>
        </div>
      </div>

      <div className={styles.confFeatures}>
        {features.map((f) => (
          <div className={styles.confFeat} key={f.label}>
            <span className={styles.confFeatLabel}>{f.label}</span>
            <span className={styles.confFeatTrack}>
              <span className={styles.confFeatFill} style={{ width: percent(f.value) }} />
            </span>
            <span className={styles.confFeatValue}>{f.real ? percent(f.value) : '—'}</span>
          </div>
        ))}
        {ctx === null && (
          <div className={styles.emptyBox} style={{ padding: 12 }}>
            Connect the backend for live confidence telemetry.
          </div>
        )}
      </div>
    </GlassPanel>
  );
}