'use client';

import React from 'react';
import { GlassPanel } from '@/components/hud/hud';
import { useOptionalCommandCenter } from '@/components/command/CommandCenterContext';

interface NetNode {
  id: string;
  label: string;
  x: number;
  y: number;
  color: string;
  r: number;
}

const NODES: NetNode[] = [
  { id: 'internet', label: 'INTERNET', x: 260, y: 30, color: '#fbbf24', r: 14 },
  { id: 'api', label: 'API', x: 260, y: 110, color: '#22d3ee', r: 16 },
  { id: 'web', label: 'WEB', x: 120, y: 190, color: '#38bdf8', r: 14 },
  { id: 'db', label: 'DATABASE', x: 256, y: 205, color: '#8b5cf6', r: 14 },
  { id: 'auth', label: 'AUTH', x: 404, y: 180, color: '#e879f9', r: 14 },
  { id: 'services', label: 'SERVICES', x: 120, y: 268, color: '#34d399', r: 13 },
  { id: 'clients', label: 'CLIENTS', x: 404, y: 266, color: '#94a3b8', r: 13 },
];

const EDGES: Array<[string, string]> = [
  ['internet', 'api'],
  ['api', 'web'],
  ['api', 'db'],
  ['api', 'auth'],
  ['api', 'services'],
  ['web', 'clients'],
  ['services', 'clients'],
];

function node(id: string): NetNode {
  return NODES.find((n) => n.id === id) as NetNode;
}

export function NetworkTopology() {
  const ctx = useOptionalCommandCenter();
  const online = ctx?.aiHealth?.status === 'ok';

  return (
    <GlassPanel title="Network Topology" icon="network" live={!!ctx} liveLabel={online ? 'Live' : 'Offline'} accent="violet">
      <svg
        viewBox="0 0 520 300"
        role="img"
        aria-label="Network topology diagram"
        style={{
          width: '100%',
          borderRadius: 8,
          border: '1px solid var(--line-dim)',
          background: 'radial-gradient(circle at 50% 50%, rgba(8,24,50,0.75), rgba(4,8,18,0.95))',
        }}
      >
        <defs>
          <radialGradient id="netBg" cx="50%" cy="45%" r="80%">
            <stop offset="0%" stopColor="rgba(15,34,66,0.9)" />
            <stop offset="100%" stopColor="rgba(4,8,18,0.95)" />
          </radialGradient>
          <filter id="netGlow" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="2.4" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        <rect width="520" height="300" fill="url(#netBg)" />

        {EDGES.map(([a, b], i) => {
          const na = node(a);
          const nb = node(b);
          const midX = (na.x + nb.x) / 2;
          const midY = (na.y + nb.y) / 2;
          const path = `M ${na.x} ${na.y} C ${na.x} ${na.y + 20}, ${nb.x} ${nb.y - 20}, ${nb.x} ${nb.y}`;
          return (
            <g key={`edge-${i}`}>
              <line x1={na.x} y1={na.y} x2={nb.x} y2={nb.y} stroke="rgba(56,189,248,0.22)" strokeWidth="0.8" />
              <circle r="1.6" fill={na.color} filter="url(#netGlow)">
                <animateMotion dur={`${2.4 + i * 0.5}s`} repeatCount="indefinite" path={path} />
              </circle>
            </g>
          );
        })}

        {NODES.map((n) => (
          <g key={n.id}>
            <circle cx={n.x} cy={n.y} r={n.r + 5} fill={n.color} opacity="0.08">
              <animate attributeName="opacity" values="0.06;0.16;0.06" dur="4s" repeatCount="indefinite" />
            </circle>
            <circle cx={n.x} cy={n.y} r={n.r} fill="rgba(6,14,28,0.95)" stroke={n.color} strokeWidth="1.4" filter="url(#netGlow)" />
            <text x={n.x} y={n.y + 3} textAnchor="middle" fontSize="6.5" fill="#dbeafe" fontFamily="ui-monospace, monospace" letterSpacing="0.5">
              {n.label}
            </text>
          </g>
        ))}
      </svg>
    </GlassPanel>
  );
}