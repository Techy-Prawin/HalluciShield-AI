'use client';

import React from 'react';
import styles from './aicore.module.css';
import { AGENTS, AGENT_MISSION } from '@/components/command/nav';
import { Icon } from '@/components/icons';
import { cx } from '@/lib/hud';

const RADIUS = 41;

interface CoreNode {
  id: string;
  label: string;
  icon: Parameters<typeof Icon>[0]['name'];
  color: string;
  x: number;
  y: number;
  angle: number;
  mission: string;
}

const NODES: CoreNode[] = AGENTS.map((agent, i) => {
  const angle = i * 40 - 90; // degrees, top start
  const rad = (angle * Math.PI) / 180;
  return {
    ...agent,
    icon: agent.icon,
    x: +(50 + RADIUS * Math.cos(rad)).toFixed(2),
    y: +(50 + RADIUS * Math.sin(rad)).toFixed(2),
    angle,
    mission: AGENT_MISSION[agent.id],
  };
});

function orientation(angle: number): 'right' | 'left' | 'top' | 'bottom' {
  const a = ((angle % 360) + 360) % 360;
  if (a > 315 || a <= 45) return 'right';
  if (a > 135 && a <= 225) return 'left';
  if (a > 45 && a <= 135) return 'bottom';
  return 'top';
}

function AgentNode({ node }: { node: CoreNode }) {
  const pos = orientation(node.angle);
  return (
    <div
      className={styles.node}
      style={{ left: `${node.x}%`, top: `${node.y}%` }}
      data-agent={node.id}
    >
      <span className={styles.nodePing} style={{ borderColor: node.color }} />
      <div className={styles.nodeIcon} style={{ color: node.color }}>
        <Icon name={node.icon} size={14} strokeWidth={1.7} />
      </div>
      <span
        className={cx(styles.nodeLabel, styles[`label-${pos}`])}
        style={{ ['--node-color' as string]: node.color }}
      >
        <span className={styles.nodeMission}>{node.mission}</span>
        {node.label}
      </span>
    </div>
  );
}

export function AICore({ compact = false }: { compact?: boolean }) {
  return (
    <div className={cx(styles.stage, compact && styles.compact)}>
      <div className={styles.core}>
        <div className={styles.coreGlow} />

        {/* Connector network + data-flow lines */}
        <svg className={styles.net} viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
          {NODES.map((n) => (
            <g key={`line-${n.id}`}>
              <line
                x1="50"
                y1="50"
                x2={n.x}
                y2={n.y}
                className={styles.spoke}
                stroke={n.color}
                opacity="0.28"
              />
              <line
                x1="50"
                y1="50"
                x2={n.x}
                y2={n.y}
                className={styles.spokeFlow}
                stroke={n.color}
                strokeDasharray="2 6"
              />
            </g>
          ))}
          {/* orbit rings */}
          <circle cx="50" cy="50" r="25" className={styles.ringStatic} />
          <circle cx="50" cy="50" r="46" className={styles.ringStaticStrong} />
        </svg>

        {/* Rotating dashed rings */}
        <div className={styles.ring} style={{ width: '58%', height: '58%', animationDuration: '26s' }} />
        <div
          className={styles.ringRev}
          style={{ width: '74%', height: '74%', animationDuration: '38s', borderColor: 'rgba(139,92,246,0.28)' }}
        />
        <div
          className={styles.ring}
          style={{ width: '90%', height: '90%', animationDuration: '52s', borderColor: 'rgba(56,189,248,0.16)' }}
        />

        {/* Centre */}
        <div className={styles.center}>
          <div className={styles.centerHalo} />
          <div className={styles.centerHex}>
            <svg viewBox="0 0 100 100" className={styles.hexSvg} aria-hidden="true">
              <defs>
                <linearGradient id="hexGrad" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stopColor="#67e8f9" />
                  <stop offset="60%" stopColor="#22d3ee" />
                  <stop offset="100%" stopColor="#3b82f6" />
                </linearGradient>
              </defs>
              <polygon
                points="50,4 93,27 93,73 50,96 7,73 7,27"
                fill="rgba(8,26,46,0.85)"
                stroke="url(#hexGrad)"
                strokeWidth="2"
              />
              <polygon
                points="50,16 83,33 83,67 50,84 17,67 17,33"
                fill="none"
                stroke="rgba(34,211,238,0.35)"
                strokeWidth="1"
              />
            </svg>
            <div className={styles.centerInner}>
              <span className={styles.centerStatus}>
                <span className={styles.centerStatusDot} />
                AI CORE ACTIVE
              </span>
              <span className={styles.centerName}>HALLUCISHIELD</span>
              <span className={styles.centerSub}>AI CORE</span>
              <span className={styles.centerId}>SHLD-7 · v1.0</span>
            </div>
          </div>
        </div>

        {/* Nodes */}
        {NODES.map((n) => (
          <AgentNode key={n.id} node={n} />
        ))}
      </div>

      <div className={styles.doctrine} aria-hidden="true">
        <span className={styles.doctrineItem} style={{ color: 'var(--red)' }}>
          <i /> DETECT
        </span>
        <span className={styles.doctrineItem} style={{ color: 'var(--cyan)' }}>
          <i /> VALIDATE
        </span>
        <span className={styles.doctrineItem} style={{ color: 'var(--green)' }}>
          <i /> REPAIR
        </span>
        <span className={styles.doctrineItem} style={{ color: 'var(--violet)' }}>
          <i /> LEARN
        </span>
      </div>
    </div>
  );
}