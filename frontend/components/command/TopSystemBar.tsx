'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import styles from './command.module.css';
import { NAV_ITEMS } from './nav';
import { Icon, type IconName } from '@/components/icons';
import { cx, formatClock, formatDate, threatLevel, fmtUptime } from '@/lib/hud';
import { useOptionalCommandCenter } from './CommandCenterContext';

export function TopSystemBar() {
  const [now, setNow] = useState<Date | null>(null);
  const ctx = useOptionalCommandCenter();
  const th = threatLevel(ctx?.monitoring ?? null);
  const backendOk = ctx?.backendHealth?.status === 'ok';
  const aiOk = ctx?.aiHealth?.status === 'ok';
  const patches = ctx?.patches?.length ?? 0;
  const scan = ctx?.scan;
  const scanConfidence = typeof scan?.confidence === 'number' ? `${scan.confidence}%` : '—';

  useEffect(() => {
    setNow(new Date());
    const timer = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  return (
    <header className={styles.topbar}>
      <div className={styles.topbarLeft}>
        <div className={styles.brandMark}>
          <div className={styles.brandShield}>
            <Icon name="shield" size={18} strokeWidth={1.9} />
          </div>
          <div className={styles.brandText}>
            <span className={styles.brandName}>HalluciShield</span>
            <span className={styles.brandSub}>Adaptive AI Security Fabric</span>
          </div>
        </div>

        <div className={styles.sep} />

        <div className={styles.topMetrics}>
          <TopMetric label="System" value={backendOk ? 'Online' : 'Offline'} color={backendOk ? 'var(--green)' : 'var(--red)'} />
          <TopMetric label="AI Core" value={aiOk ? 'Active' : 'Idle'} color={aiOk ? 'var(--cyan)' : 'var(--amber)'} />
          <TopMetric label="Threat Level" value={th.label} color={th.color} />
          <TopMetric label="Pipeline" value={scan ? (scan.status ?? 'Idle') : 'Idle'} color={scan && (scan.status === 'COMPLETED' || scan.status === 'SUCCESS') ? 'var(--green)' : scan?.status === 'FAILED' ? 'var(--red)' : 'var(--text-2)'} />
          <TopMetric label="Patches" value={patches ? String(patches).padStart(2, '0') : '00'} color={patches ? 'var(--green)' : 'var(--text-3)'} />
          <TopMetric label="Confidence" value={scanConfidence} color="var(--violet)" />
          <TopMetric label="Uptime" value={fmtUptime(ctx?.monitoring?.uptime_seconds)} color="var(--sky)" />
        </div>
      </div>

      <div className={styles.topbarRight}>
        <div className={styles.clockBlock}>
          <span className={styles.clockTime}>{now ? formatClock(now) : '--:--:--'}</span>
          <span className={styles.clockDate}>{now ? formatDate(now).toUpperCase() : '--- --, ----'}</span>
        </div>
        <div className={styles.sep} />
        <span className={styles.utilityBtn} title="Notifications">
          <Icon name="bell" size={15} />
          <span className={styles.notifDot} />
        </span>
        <span className={styles.utilityBtn} title="System settings">
          <Icon name="settings" size={15} />
        </span>
        <div className={styles.avatarWrap}>
          <div className={styles.avatar}>PA</div>
          <div className={styles.avatarText}>
            <span className={styles.avatarName}>Admin</span>
            <span className={styles.avatarRole}>Security Analyst</span>
          </div>
        </div>
        <span className={styles.utilityBtn}>
          <Icon name="menu" size={16} />
        </span>
      </div>
    </header>
  );
}

function TopMetric({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className={styles.topMetric}>
      <span className={styles.topMetricLabel}>{label}</span>
      <span className={styles.topMetricValue} style={{ color }}>
        {value}
      </span>
    </div>
  );
}

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className={styles.sidebar}>
      <div className={styles.sidebarCore}>
        <div className={styles.sidebarTitle}>
          <Icon name="hexagon" size={13} />
          <span>Security Fabric</span>
        </div>

        <nav className={styles.sidebarNav} aria-label="Primary">
          {NAV_ITEMS.map((item) => {
            const active = item.href === pathname;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cx(styles.navLink, active && styles.navLinkActive)}
                data-testid={`nav-${item.href}`}
              >
                <span className={styles.navLinkIcon}>
                  <Icon name={item.icon as IconName} size={15} />
                </span>
                <span className={styles.navLinkLabel}>{item.label}</span>
                <span className={styles.navLinkChevron}>
                  <Icon name="chevronRight" size={12} />
                </span>
              </Link>
            );
          })}
        </nav>
      </div>

      <div className={styles.sidebarFooter}>
        <div className={styles.sidebarFootRow}>
          <Icon name="lock" size={12} />
          <span>Encrypted Session</span>
        </div>
        <div className={styles.sidebarFootRow}>
          <Icon name="shield" size={12} />
          <span>SOC · Sector 7</span>
        </div>
      </div>
    </aside>
  );
}