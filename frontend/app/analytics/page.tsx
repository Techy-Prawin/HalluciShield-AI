'use client';

import React from 'react';
import styles from '@/components/command/heroWorkflow.module.css';
import { CommandShell } from '@/components/command/CommandShell';
import { PageHeader } from '@/components/command/HeroWorkflow';
import { GlassPanel } from '@/components/hud/hud';
import { useCommandCenter } from '@/components/command/CommandCenterContext';
import { ExperimentAnalytics } from '@/app/components/ExperimentAnalytics';

function Breakdown({ title, icon, data, order }: { title: string; icon: 'chart' | 'db' | 'alert'; data?: Record<string, number>; order: string[] }) {
  const total = Object.values(data ?? {}).reduce((a, b) => a + b, 0) || 0;
  return (
    <GlassPanel title={title} icon={icon} live accent="blue" scrollable>
      {total === 0 ? (
        <div style={{ fontFamily: 'var(--mono)', fontSize: 10.5, color: 'var(--text-3)' }}>No data recorded yet.</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {order
            .map((k) => ({ k, v: data?.[k] ?? 0, width: total ? (data![k] ?? 0) / total : 0 }))
            .sort((a, b) => b.v - a.v)
            .map(({ k, v, width }) => (
              <div key={k} style={{ display: 'grid', gridTemplateColumns: '110px 1fr 40px', gap: 10, alignItems: 'center' }}>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 9.5, color: 'var(--text-3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {k}
                </span>
                <span style={{ height: 7, borderRadius: 999, background: 'rgba(120,160,230,0.12)', overflow: 'hidden' }}>
                  <span style={{ display: 'block', height: '100%', width: `${Math.max(2, width * 100)}%`, borderRadius: 999, background: 'linear-gradient(90deg, var(--blue), var(--cyan))', boxShadow: '0 0 8px -2px var(--cyan)' }} />
                </span>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text-1)', textAlign: 'right' }}>{v}</span>
              </div>
            ))}
        </div>
      )}
    </GlassPanel>
  );
}

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const TYPE_SEV = ['LLM_FALLBACK', 'LLM_TIMEOUT', 'INJECTION', 'UNAUTHORIZED', 'RATE_LIMIT', 'ANOMALY', 'INFO'];

export default function AnalyticsPage() {
  const ctx = useCommandCenter();
  const eps = ctx.monitoring?.top_anomaly_endpoints ?? [];

  return (
    <CommandShell>
      <PageHeader eyebrow="RESEARCH &amp; TELEMETRY" title="ANALYTICS" icon="chart">
        Benchmark experiment results from the IEEE evaluation suite alongside live runtime distributions.
      </PageHeader>

      <div className={styles.grid2}>
        <Breakdown title="Events by Type" icon="chart" data={ctx.monitoring?.events_by_type} order={TYPE_SEV} />
        <Breakdown title="Alerts by Severity" icon="alert" data={ctx.monitoring?.alerts_by_severity} order={SEV_ORDER} />
      </div>

      {eps.length > 0 && (
        <GlassPanel title="Top Anomaly Endpoints" icon="route" live accent="red">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {eps.map((ep, i) => (
              <div key={`${ep.endpoint}-${i}`} style={{ display: 'flex', justifyContent: 'space-between', gap: 10, padding: '9px 12px', border: '1px solid var(--line-dim)', borderRadius: 8, fontFamily: 'var(--mono)', fontSize: 10.5, color: 'var(--text-1)' }}>
                <span className="mono" style={{ color: 'var(--cyan)', wordBreak: 'break-all' }}>{ep.endpoint}</span>
                <span style={{ color: 'var(--text-3)' }}>{ep.count ?? 0} HITS</span>
              </div>
            ))}
          </div>
        </GlassPanel>
      )}

      <GlassPanel title="IEEE Evaluation Suite" icon="flask" accent="violet">
        <ExperimentAnalytics />
      </GlassPanel>
    </CommandShell>
  );
}