'use client';

import React from 'react';
import styles from '@/components/command/heroWorkflow.module.css';
import { CommandShell } from '@/components/command/CommandShell';
import { PageHeader } from '@/components/command/HeroWorkflow';
import { GlassPanel, RingGauge } from '@/components/hud/hud';
import { useCommandCenter } from '@/components/command/CommandCenterContext';
import { ConfidenceMetrics } from '@/components/panels/ConfidenceMetrics';
import { ThreatIntelligence } from '@/components/panels/ThreatIntelligence';
import { threatLevel } from '@/lib/hud';

export default function ConfidencePage() {
  const ctx = useCommandCenter();
  const th = threatLevel(ctx.monitoring);

  return (
    <CommandShell>
      <PageHeader eyebrow="CALIBRATED JUDGEMENT" title="CONFIDENCE ENGINE" icon="gauge">
        The adaptive confidence engine (ACE) weighs every decision against measured feature performance.
      </PageHeader>

      <div className={styles.grid2}>
        <ConfidenceMetrics />
        <GlassPanel title="Calibration Overview" icon="target" accent="cyan">
          <div style={{ display: 'flex', gap: 22, alignItems: 'center', flexWrap: 'wrap', justifyContent: 'space-between' }}>
            <RingGauge value={typeof ctx.scan?.confidence === 'number' ? ctx.scan.confidence : 0} label="Mean Confidence" size={140} color="var(--violet)" />
            <RingGauge
              value={typeof ctx.scan?.riskScore === 'number' ? ctx.scan.riskScore : 0}
              label={typeof ctx.scan?.riskScore === 'number' ? 'Risk Score' : 'Risk Score'}
              size={140}
              color={typeof ctx.scan?.riskScore === 'number' && ctx.scan.riskScore > 70 ? 'var(--red)' : typeof ctx.scan?.riskScore === 'number' && ctx.scan.riskScore > 40 ? 'var(--amber)' : 'var(--green)'}
            />
            <div className="mono" style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 10.5, color: 'var(--text-3)' }}>
              <span>THREAT LEVEL · <b style={{ color: th.color }}>{th.label.toUpperCase()}</b></span>
              <span>TOTAL EVENTS · {ctx.monitoring?.total_events ?? 0}</span>
              <span>TOTAL ALERTS · {ctx.monitoring?.total_alerts ?? 0}</span>
              <span>UPTIME · {ctx.monitoring?.uptime_seconds !== undefined ? `${ctx.monitoring.uptime_seconds}s` : '—'}</span>
            </div>
          </div>
        </GlassPanel>
      </div>

      <ThreatIntelligence />
    </CommandShell>
  );
}