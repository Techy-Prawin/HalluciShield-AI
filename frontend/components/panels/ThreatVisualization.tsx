'use client';

import React from 'react';
import styles from './panels.module.css';
import { GlassPanel } from '@/components/hud/hud';
import { useOptionalCommandCenter } from '@/components/command/CommandCenterContext';

const SOURCES = [
  { x: 42, y: 54 },
  { x: 96, y: 26 },
  { x: 142, y: 78 },
  { x: 522, y: 40 },
  { x: 486, y: 96 },
  { x: 558, y: 150 },
];

const TARGETS = [
  { x: 300, y: 128 },
  { x: 344, y: 162 },
  { x: 258, y: 176 },
  { x: 312, y: 200 },
];

/* Abstract landmass blobs (decorative). */
const LANDS = [
  'M60 150 C 78 128, 128 122, 152 136 C 178 150, 196 176, 176 204 C 154 234, 104 232, 82 208 C 62 186, 44 172, 60 150 Z',
  'M150 56 C 172 30, 222 28, 244 52 C 264 74, 256 106, 228 116 C 196 128, 164 122, 152 94 C 142 72, 132 76, 150 56 Z',
  'M388 44 C 414 24, 458 30, 472 54 C 486 78, 476 108, 448 116 C 420 124, 396 112, 392 88 C 388 68, 368 62, 388 44 Z',
  'M352 176 C 372 156, 416 156, 436 176 C 456 198, 448 234, 420 242 C 392 250, 364 238, 356 214 C 348 196, 336 192, 352 176 Z',
  'M470 180 C 494 168, 528 172, 536 192 C 544 212, 530 234, 508 238 C 488 242, 468 226, 466 206 C 464 192, 452 188, 470 180 Z',
];

export function ThreatVisualization({ className }: { className?: string }) {
  const ctx = useOptionalCommandCenter();
  const threatCount = ctx?.monitoring?.total_alerts ?? 0;
  const eventCount = ctx?.monitoring?.total_events ?? 0;
  const arcCount = Math.max(1, Math.min(6, threatCount > 0 ? threatCount : 1));
  const riskScore = typeof ctx?.scan?.riskScore === 'number' ? ctx.scan.riskScore : null;

  return (
    <GlassPanel title="Global Threat Visualization" icon="globe" live accent="cyan" className={className}>
      <svg className={styles.tviz} viewBox="0 0 600 300" role="img" aria-label="Global threat activity map">
        <defs>
          <radialGradient id="tvizBg" cx="50%" cy="45%" r="75%">
            <stop offset="0%" stopColor="#0d2446" />
            <stop offset="100%" stopColor="#040810" />
          </radialGradient>
          <linearGradient id="arcGrad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#f87171" />
            <stop offset="50%" stopColor="#fbbf24" />
            <stop offset="100%" stopColor="#22d3ee" />
          </linearGradient>
          <filter id="arcGlow" x="-20%" y="-60%" width="140%" height="220%">
            <feGaussianBlur stdDeviation="2" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        <rect x="0" y="0" width="600" height="300" fill="url(#tvizBg)" />

        <g opacity="0.5">
          {[0, 1, 2, 3, 4].map((i) => (
            <g key={`grid-${i}`}>
              <line x1="0" y1={60 + i * 45} x2="600" y2={60 + i * 45} stroke="rgba(56,189,248,0.1)" strokeWidth="0.5" />
              <line x1={100 + i * 100} y1="0" x2={100 + i * 100} y2="300" stroke="rgba(56,189,248,0.1)" strokeWidth="0.5" />
            </g>
          ))}
        </g>

        {LANDS.map((d, i) => (
          <path key={`land-${i}`} d={d} fill="rgba(13,40,74,0.55)" stroke="rgba(56,189,248,0.22)" strokeWidth="0.7" />
        ))}

        {/* Attack arcs */}
        {Array.from({ length: arcCount }).map((_, i) => {
          const src = SOURCES[i % SOURCES.length];
          const dst = TARGETS[i % TARGETS.length];
          const midX = (src.x + dst.x) / 2;
          const controlY = Math.min(src.y, dst.y) - 46 - i * 6;
          return (
            <g key={`arc-${i}`} opacity={0.9}>
              <path
                d={`M ${src.x} ${src.y} Q ${midX} ${controlY} ${dst.x} ${dst.y}`}
                fill="none"
                stroke="url(#arcGrad)"
                strokeWidth="1.4"
                filter="url(#arcGlow)"
                strokeDasharray="5 4"
              >
                <animate attributeName="stroke-dashoffset" from="18" to="0" dur={`${2.6 + i * 0.7}s`} repeatCount="indefinite" />
              </path>
              <circle cx={src.x} cy={src.y} r="2.6" fill="#f87171">
                <animate attributeName="r" values="2.6;4;2.6" dur="2s" begin={`${i * 0.3}s`} repeatCount="indefinite" />
              </circle>
              <circle cx={dst.x} cy={dst.y} r="2.6" fill="#22d3ee">
                <animate attributeName="r" values="2.6;4;2.6" dur="2s" begin={`${i * 0.4}s`} repeatCount="indefinite" />
              </circle>
            </g>
          );
        })}

        {/* shield anchor at target region */}
        <g transform="translate(300,138)">
          <path
            d="M0 -14 L12 -7 L12 3 C12 14 4 20 0 22 C-4 20 -12 14 -12 3 L-12 -7 Z"
            fill="rgba(34,211,238,0.08)"
            stroke="rgba(34,211,238,0.8)"
            strokeWidth="1"
          />
        </g>
      </svg>

      <div className={styles.tvizMetrics}>
        <TvizMetric label="Active Threats" value={eventCount >= 0 ? String(eventCount) : '—'} accent="var(--red)" />
        <TvizMetric label="Blocked Attacks" value="—" accent="var(--green)" />
        <TvizMetric label="Countries Targeted" value="—" accent="var(--sky)" />
        <TvizMetric label="Risk Score" value={riskScore !== null ? String(riskScore) : '—'} accent="var(--amber)" />
      </div>
    </GlassPanel>
  );
}

function TvizMetric({ label, value, accent }: { label: string; value: string; accent: string }) {
  return (
    <div className={styles.tvizMetric}>
      <span className={styles.tvizMetricLabel}>{label}</span>
      <span className={styles.tvizMetricValue} style={{ color: accent }}>
        {value}
      </span>
    </div>
  );
}