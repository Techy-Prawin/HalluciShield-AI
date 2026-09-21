import React, { useEffect, useRef, useState } from 'react';
import styles from './hud.module.css';
import { cx, prefersReducedMotion } from '@/lib/hud';
import { Icon, type IconName } from '@/components/icons';

/* ------------------------------------------------------------------ */
/* GlassPanel — the shared panel chrome.                              */
/* ------------------------------------------------------------------ */

interface GlassPanelProps {
  title: string;
  icon?: IconName;
  live?: boolean;
  liveLabel?: string;
  right?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
  accent?: 'cyan' | 'blue' | 'violet' | 'magenta' | 'green' | 'amber' | 'red';
  scrollable?: boolean;
  grow?: boolean;
}

export function GlassPanel({
  title,
  icon,
  live,
  liveLabel = 'Live',
  right,
  children,
  className,
  bodyClassName,
  accent = 'cyan',
  scrollable,
  grow,
}: GlassPanelProps) {
  return (
    <section
      className={cx(styles.panel, styles[`accent-${accent}`], grow && styles.grow, className)}
    >
      <header className={styles.panelHeader}>
        <div className={styles.panelHeaderLeft}>
          {icon && (
            <span className={styles.panelIcon}>
              <Icon name={icon} size={13} />
            </span>
          )}
          <h3 className={styles.panelTitle}>{title}</h3>
          {right}
        </div>
        {live && (
          <span className={styles.panelLive}>
            <span className={styles.panelLiveDot} />
            {liveLabel}
          </span>
        )}
      </header>
      <div className={cx(styles.panelBody, scrollable && styles.panelScroll, bodyClassName)}>
        {children}
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* StatusDot — pulsing status indicator.                              */
/* ------------------------------------------------------------------ */

interface StatusDotProps {
  color?: string;
  size?: number;
  pulse?: boolean;
  label?: string;
  className?: string;
}

export function StatusDot({ color = 'var(--green)', size = 8, pulse = true, label, className }: StatusDotProps) {
  return (
    <span className={cx(styles.dotWrap, className)} title={label} aria-label={label}>
      {pulse && <span className={styles.dotPing} style={{ borderColor: color }} />}
      <span
        className={styles.dotCore}
        style={{ width: size, height: size, background: color, boxShadow: `0 0 8px ${color}` }}
      />
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* MetricCounter — animated count / count-up.                         */
/* ------------------------------------------------------------------ */

interface CounterProps {
  value: number;
  decimals?: number;
  duration?: number;
  prefix?: string;
  suffix?: string;
}

export function MetricCounter({ value, decimals = 1, duration = 700, prefix = '', suffix = '' }: CounterProps) {
  const [display, setDisplay] = useState(0);
  const from = useRef(0);
  const reduced = prefersReducedMotion();

  useEffect(() => {
    if (reduced) {
      setDisplay(value);
      return;
    }
    let raf = 0;
    const start = performance.now();
    const delta = value - from.current;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(from.current + delta * eased);
      if (t < 1) raf = requestAnimationFrame(tick);
      else from.current = value;
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value, duration, reduced]);

  const text = display.toFixed(decimals);

  return (
    <span>
      {prefix}
      {text}
      {suffix}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* RingGauge — SVG circular progress.                                 */
/* ------------------------------------------------------------------ */

interface RingGaugeProps {
  value?: number;
  label?: string;
  sublabel?: string;
  size?: number;
  stroke?: number;
  color?: string;
  trackColor?: string;
  className?: string;
}

export function RingGauge({
  value,
  label = '%',
  sublabel,
  size = 120,
  stroke = 8,
  color = 'var(--cyan)',
  trackColor = 'rgba(120,160,230,0.12)',
  className,
}: RingGaugeProps) {
  const [progress, setProgress] = useState(0);
  const reduced = prefersReducedMotion();
  const target = Math.max(0, Math.min(100, value ?? 0));

  useEffect(() => {
    if (reduced) {
      setProgress(target);
      return;
    }
    let raf = 0;
    const start = performance.now();
    const duration = 850;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setProgress(target * eased);
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, reduced]);

  const r = (size - stroke) / 2;
  const circumference = 2 * Math.PI * r;
  const offset = circumference * (1 - progress / 100);
  const numeric = value === undefined || value === null || Number.isNaN(value) ? null : value.toFixed(1);

  return (
    <div className={cx(styles.ringWrap, className)} style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={trackColor}
          strokeWidth={stroke}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ filter: `drop-shadow(0 0 6px ${color})` }}
        />
      </svg>
      <div className={styles.ringCenter}>
        <span className={styles.ringValue} style={{ color }}>
          {numeric === null ? '—' : `${numeric}%`}
        </span>
        <span className={styles.ringLabel}>{label}</span>
        {sublabel && <span className={styles.ringSub}>{sublabel}</span>}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* SparkWave — subtle SVG live waveform.                              */
/* ------------------------------------------------------------------ */

interface SparkWaveProps {
  height?: number;
  color?: string;
  points?: number;
}

export function SparkWave({ height = 40, color = 'var(--cyan)', points = 90 }: SparkWaveProps) {
  const seed = Array.from({ length: points }, (_, i) => {
    const wave = Math.sin(i * 0.43) * 0.18 + Math.sin(i * 0.11 + 1.4) * 0.12;
    return Math.max(0.08, Math.min(0.92, 0.5 + wave));
  });
  return (
    <svg className={styles.sparkWave} viewBox={`0 0 ${points} 40`} preserveAspectRatio="none" style={{ height }}>
      <defs>
        <linearGradient id="sparkFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.45" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <g opacity="0.35">
        {seed.map((v, i) => (
          <rect key={i} x={i} y={v * 40} width="0.8" height={40 - v * 40} fill="url(#sparkFill)" />
        ))}
      </g>
      {[9, 18, 27, 36].map((y) => (
        <line key={y} x1="0" y1={y} x2={points} y2={y} stroke={color} strokeOpacity="0.14" strokeWidth="0.4" />
      ))}
    </svg>
  );
}