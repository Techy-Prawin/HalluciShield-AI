'use client';

import React from 'react';
import styles from './panels.module.css';
import { GlassPanel } from '@/components/hud/hud';
import { Icon, type IconName } from '@/components/icons';
import { useOptionalCommandCenter } from '@/components/command/CommandCenterContext';
import { cx, severityMeta, timeAgo } from '@/lib/hud';

const EVENT_ICON: Record<string, IconName> = {
  API_ANOMALY: 'route',
  REPEATED_SUSPICIOUS_REQUEST: 'scan',
  ERROR_SPIKE: 'alert',
  AUTH_ANOMALY: 'lock',
  SECURITY_EVENT: 'shield',
  PERFORMANCE_REGRESSION: 'activity',
};

export function ThreatIntelligence({ className }: { className?: string }) {
  const ctx = useOptionalCommandCenter();
  const alerts = ctx?.alerts ?? [];
  const connected = ctx !== null && (ctx?.alerts?.length ?? 0) >= 0;

  return (
    <GlassPanel
      title="Live Threat Intelligence"
      icon="activity"
      live={connected}
      liveLabel={connected ? 'Real-Time' : 'Offline'}
      accent="red"
      className={className}
    >
      {alerts.length === 0 ? (
        <div className={styles.emptyBox}>
          <Icon name="shield" size={22} style={{ color: 'var(--text-3)' }} />
          <span>
            {ctx === null
              ? 'No live feed connected. Start the backend + AI engine to stream alerts.'
              : 'No active alerts — system nominal. Monitoring events, when raised by the backend, appear here.'}
          </span>
        </div>
      ) : (
        <div className={styles.threatList}>
          {alerts.map((alert, i) => {
            const meta = severityMeta(alert.severity);
            const icon = EVENT_ICON[alert.event_type ?? ''] ?? 'alert';
            return (
              <div
                className={styles.threatRow}
                key={alert.alert_id ?? `alert-${i}`}
                style={{ animationDelay: `${Math.min(i * 60, 450)}ms` }}
              >
                <span className={styles.threatIcon} style={{ color: meta.color, borderColor: meta.color, background: `${meta.color}1a` }}>
                  <Icon name={icon} size={14} />
                </span>
                <div className={styles.threatMain}>
                  <span className={styles.threatTitle}>
                    {alert.vulnerability_type ?? alert.event_type ?? 'Security Event'}
                    {alert.event_type === 'REPEATED_SUSPICIOUS_REQUEST' && <span className={styles.simBadge}>REPEATED</span>}
                  </span>
                  <span className={styles.threatDesc}>{alert.vulnerability_description ?? alert.affected_endpoint ?? '—'}</span>
                </div>
                <div className={styles.threatRight}>
                  <span
                    className={cx(styles.tag)}
                    style={{ color: meta.color, border: `1px solid ${meta.color}`, background: `${meta.color}14` }}
                  >
                    {meta.label.toUpperCase()}
                  </span>
                  <span className={styles.threatTime}>{timeAgo(alert.created_at)}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </GlassPanel>
  );
}