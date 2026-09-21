'use client';

import React, { useMemo, useState } from 'react';
import styles from './panels.module.css';
import { GlassPanel } from '@/components/hud/hud';
import { Icon } from '@/components/icons';
import { useOptionalCommandCenter } from '@/components/command/CommandCenterContext';
import { severityMeta, formatTime, humanize, cx } from '@/lib/hud';
import type { RuntimeEventRecord } from '@/lib/api';

type LogTab = 'ALL' | 'SECURITY' | 'AI' | 'PATCH' | 'RUNTIME';

const TABS: LogTab[] = ['ALL', 'SECURITY', 'AI', 'PATCH', 'RUNTIME'];

const TAB_PREDICATE: Record<Exclude<LogTab, 'ALL'>, (e: RuntimeEventRecord) => boolean> = {
  SECURITY: (e) => ['SECURITY_EVENT', 'REPEATED_SUSPICIOUS_REQUEST', 'AUTH_ANOMALY'].includes(e.event_type ?? ''),
  AI: (e) => ['API_ANOMALY', 'ERROR_SPIKE'].includes(e.event_type ?? ''),
  PATCH: (e) => ['PERFORMANCE_REGRESSION'].includes(e.event_type ?? ''),
  RUNTIME: (e) => ['API_ANOMALY'].includes(e.event_type ?? ''),
};

export function SystemLogs({ className }: { className?: string }) {
  const ctx = useOptionalCommandCenter();
  const [tab, setTab] = useState<LogTab>('ALL');
  const events = ctx?.events ?? [];

  const rows = useMemo(() => {
    if (tab === 'ALL') return events;
    return events.filter(TAB_PREDICATE[tab]);
  }, [events, tab]);

  return (
    <GlassPanel
      title="System Logs"
      icon="terminal"
      accent="cyan"
      className={className}
      right={
        <div className={styles.logTabs}>
          {TABS.map((t) => (
            <button
              key={t}
              className={cx(styles.logTab, tab === t && styles.logTabActive)}
              onClick={() => setTab(t)}
            >
              {t}
            </button>
          ))}
        </div>
      }
    >
      {rows.length === 0 ? (
        <div className={styles.emptyBox}>
          <Icon name="terminal" size={22} style={{ color: 'var(--text-3)' }} />
          <span>
            {ctx === null
              ? 'Log pipeline disconnected — start the AI engine for runtime events.'
              : `No ${tab.toLowerCase()} events recorded yet. Runtime events stream from the AI monitoring agent.`}
          </span>
        </div>
      ) : (
        <div className={styles.logRows}>
          {rows.map((e, i) => {
            const meta = severityMeta(e.severity);
            return (
              <div className={styles.logRow} key={e.event_id ?? `${tab}-${i}`}>
                <span className={styles.logTime}>{formatTime(e.detected_at)}</span>
                <span
                  className={cx(styles.sevTag)}
                  style={{ color: meta.color, background: `${meta.color}18`, border: `1px solid ${meta.color}55` }}
                >
                  {meta.label.toUpperCase()}
                </span>
                <span className={styles.logSrc}>{humanize(e.event_type, 'RUNTIME')}</span>
                <span className={styles.logMsg}>
                  {e.description ?? `${e.method ?? ''} ${e.endpoint ?? ''}`.trim()}
                </span>
                <span className={styles.logMeta}>
                  {e.status_code ? `HTTP ${e.status_code} · ` : ''}
                  {e.response_time_ms ? `${e.response_time_ms}ms` : ''}
                  {e.endpoint ? ` · ${e.endpoint}` : ''}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </GlassPanel>
  );
}