'use client';

import React from 'react';
import styles from '@/components/command/heroWorkflow.module.css';
import { CommandShell } from '@/components/command/CommandShell';
import { PageHeader } from '@/components/command/HeroWorkflow';
import { GlassPanel } from '@/components/hud/hud';
import { useCommandCenter } from '@/components/command/CommandCenterContext';
import { Icon } from '@/components/icons';
import { ConfidenceMetrics } from '@/components/panels/ConfidenceMetrics';
import { ActiveAgents } from '@/components/panels/SystemHealth';

export default function LearningPage() {
  const ctx = useCommandCenter();
  const lr = ctx.learningSummary;

  const stats = [
    { label: 'LEARNING RECORDS', value: lr?.total_records, color: 'var(--cyan)' },
    { label: 'PATTERNS INDEXED', value: lr?.total_patterns, color: 'var(--violet)' },
    { label: 'ADJUSTMENTS', value: lr?.recent_adjustments?.length, color: 'var(--magenta)' },
    { label: 'MODEL VERSION', value: lr?.model_version, color: 'var(--green)', asText: true },
  ];

  return (
    <CommandShell>
      <PageHeader eyebrow="EVERY SCAN FEEDS THE CORE" title="ADAPTIVE LEARNING" icon="function">
        The confidence engine recalibrates dynamically as validation outcomes and runtime alerts accumulate.
      </PageHeader>

      <GlassPanel title="Knowledge State" icon="brain" live={!!lr} liveLabel={lr ? 'ACTIVE' : 'OFFLINE'} accent="violet">
        {lr === null && (
          <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-3)' }}>
            AI engine offline — learning telemetry unavailable. Start the FastAPI engine to observe live adaptation.
          </div>
        )}
        {lr !== null && (
          <div className={styles.grid2}>
            {stats.map((s) => (
              <div key={s.label} style={{ display: 'flex', flexDirection: 'column', gap: 6, padding: '14px 16px', border: '1px solid var(--line-dim)', borderRadius: 10, background: 'rgba(10,20,40,0.5)' }}>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 8.5, letterSpacing: '0.16em', color: 'var(--text-3)' }}>{s.label}</span>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 20, fontWeight: 800, color: s.color }}>
                  {s.asText ? String(s.value ?? '—') : Number(s.value ?? 0).toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </GlassPanel>

      <div className={styles.grid2}>
        <ConfidenceMetrics />
        <GlassPanel title="Adaptation Loop" icon="refresh" accent="magenta">
          <ul style={{ display: 'flex', flexDirection: 'column', gap: 10, listStyle: 'none' }}>
            {[
              ['OBSERVE', 'Scan verdicts + sandbox outcomes are written to the learning store', 'var(--cyan)'],
              ['REWEIGHT', 'ACE feature weights shift toward measured reliability', 'var(--violet)'],
              ['CALIBRATE', 'Confidence thresholds retune against historical success', 'var(--magenta)'],
              ['FORGET', 'Stale patterns decay to avoid confidence drift', 'var(--amber)'],
            ].map(([step, desc, color]) => (
              <li key={step} style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                <Icon name="function" size={13} style={{ color, marginTop: 1, flexShrink: 0 }} />
                <span style={{ fontSize: 11.5, color: 'var(--text-2)', lineHeight: 1.55 }}>
                  <b style={{ color, fontFamily: 'var(--mono)', marginRight: 8 }}>{step}</b>
                  {desc}
                </span>
              </li>
            ))}
          </ul>
        </GlassPanel>
      </div>

      <ActiveAgents />
    </CommandShell>
  );
}