import type { MonitoringSummary } from './api';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'nominal';

export const cx = (...parts: Array<string | false | null | undefined>): string =>
  parts.filter(Boolean).join(' ');

export interface SeverityMeta {
  severity: Severity;
  label: string;
  color: string;
}

export function classifySeverity(raw?: string | null): Severity {
  const value = (raw || '').toUpperCase();
  if (value === 'CRITICAL') return 'critical';
  if (value === 'HIGH') return 'high';
  if (value === 'MEDIUM') return 'medium';
  if (value === 'LOW') return 'low';
  return 'info';
}

export function severityMeta(raw?: string | null): SeverityMeta {
  const severity = classifySeverity(raw);
  switch (severity) {
    case 'critical':
      return { severity, label: 'Critical', color: 'var(--red)' };
    case 'high':
      return { severity, label: 'High', color: 'var(--amber)' };
    case 'medium':
      return { severity, label: 'Medium', color: 'var(--amber)' };
    case 'low':
      return { severity, label: 'Low', color: 'var(--cyan)' };
    case 'nominal':
      return { severity, label: 'Nominal', color: 'var(--green)' };
    default:
      return { severity, label: 'Info', color: 'var(--sky)' };
  }
}

export function threatLevel(summary: MonitoringSummary | null): SeverityMeta {
  if (!summary || summary.total_alerts === undefined) return { severity: 'nominal', label: 'Offline', color: 'var(--text-3)' };
  if (summary.total_alerts === 0) return { severity: 'nominal', label: 'Low', color: 'var(--green)' };
  const alertsBySeverity = summary.alerts_by_severity ?? {};
  if ((alertsBySeverity.CRITICAL || 0) > 0) return { severity: 'critical', label: 'Critical', color: 'var(--red)' };
  if ((alertsBySeverity.HIGH || 0) > 0) return { severity: 'high', label: 'Elevated', color: 'var(--amber)' };
  if ((alertsBySeverity.MEDIUM || 0) > 0) return { severity: 'medium', label: 'Moderate', color: 'var(--amber)' };
  return { severity: 'low', label: 'Low', color: 'var(--cyan)' };
}

export function padCount(value: number | undefined | null, length = 2): string {
  const n = Math.max(0, Math.floor(value ?? 0));
  return String(n).padStart(length, '0');
}

export function formatTime(date?: string | null): string {
  if (!date) return '--:--:--';
  const d = new Date(date);
  if (Number.isNaN(d.getTime())) return '--:--:--';
  return d.toLocaleTimeString([], { hour12: false });
}

export function formatClock(date: Date): string {
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

export function formatDate(date: Date): string {
  return date.toLocaleDateString([], { month: 'short', day: '2-digit', year: 'numeric' });
}

export function timeAgo(date?: string | null): string {
  if (!date) return '—';
  const d = new Date(date);
  if (Number.isNaN(d.getTime())) return '—';
  const seconds = Math.floor((Date.now() - d.getTime()) / 1000);
  if (seconds < 5) return 'now';
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return formatTime(date);
}

export function humanize(key = '', fallback = ''): string {
  if (!key) return fallback;
  return key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

export function round1(value: number | undefined | null): string {
  if (value === undefined || value === null || Number.isNaN(value)) return '—';
  return value.toFixed(1);
}

export function percent(value: number | undefined | null): string {
  if (value === undefined || value === null || Number.isNaN(value)) return '—';
  return `${value.toFixed(1)}%`;
}

export function fmtUptime(seconds: number | undefined | null): string {
  if (!seconds || seconds <= 0) return '—';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${mins}m`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

/** A robust clamp helper for CSS-friendly values. */
export function clampPercent(value: number | undefined | null, fallback = 0): number {
  const v = value ?? fallback;
  if (Number.isNaN(v)) return fallback;
  return Math.max(0, Math.min(100, v));
}

/** Component-provided animation-friendly hook resolver for reduced motion. */
export function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || !window.matchMedia) return false;
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}