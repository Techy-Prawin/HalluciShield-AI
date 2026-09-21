'use client';

import React from 'react';
import styles from '@/components/command/heroWorkflow.module.css';
import { CommandShell } from '@/components/command/CommandShell';
import { PageHeader } from '@/components/command/HeroWorkflow';
import { GlassPanel } from '@/components/hud/hud';
import { AICore } from '@/components/core/AICore';
import { SystemHealth, ActiveAgents } from '@/components/panels/SystemHealth';
import { NetworkTopology } from '@/components/panels/NetworkTopology';
import { useCommandCenter } from '@/components/command/CommandCenterContext';

const SERVICES = [
  { name: 'Express Backend API', host: 'http://localhost:4000', protocol: 'REST · JSON', state: 'orchestration' },
  { name: 'Python FastAPI AI Engine', host: 'http://localhost:8000', protocol: 'REST · JSON', state: 'agents' },
  { name: 'PostgreSQL Database', host: 'localhost:5432 / hallucishield_db', protocol: 'SQL', state: 'persistence' },
  { name: 'Docker Sandbox', host: 'isolated execution runtime', protocol: 'OCI', state: 'validation' },
  { name: 'Next.js Frontend', host: 'hallucishield command center', protocol: 'App Router · RSC', state: 'shell' },
  { name: 'ACE Learning Store', host: 'embedded in AI engine', protocol: 'JSON', state: 'adaptation' },
];

export default function SystemPage() {
  const ctx = useCommandCenter();
  const backendOk = ctx.backendHealth?.status === 'ok';
  const aiOk = ctx.aiHealth?.status === 'ok';

  return (
    <CommandShell>
      <PageHeader eyebrow="INFRASTRUCTURE FABRIC" title="SYSTEM" icon="server">
        Service mesh, health probes and the neural core that powers the command center.
      </PageHeader>

      <div className={styles.wideRow}>
        <SystemHealth />
        <NetworkTopology />
      </div>

      <div className={styles.grid2}>
        <AICore />
        <GlassPanel title="Service Registry" icon="server" live accent="blue" scrollable>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {SERVICES.map((s) => {
              const ok = s.state === 'shell' ? true : s.state === 'orchestration' ? backendOk : s.state === 'agents' ? aiOk : false;
              return (
                <div key={s.name} className="mono" style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 12px', border: '1px solid var(--line-dim)', borderRadius: 8, background: 'rgba(10,20,40,0.45)' }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', flexShrink: 0, background: ok ? 'var(--green)' : 'var(--amber)', boxShadow: ok ? '0 0 8px var(--green)' : '0 0 8px var(--amber)' }} />
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
                    <span style={{ fontSize: 11.5, fontWeight: 700, color: 'var(--text-0)' }}>{s.name}</span>
                    <span style={{ fontSize: 9.5, color: 'var(--text-3)' }}>{s.host}</span>
                  </div>
                  <span style={{ marginLeft: 'auto', fontSize: 8.5, letterSpacing: '0.12em', color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                    {s.protocol} · {s.state.toUpperCase()}
                  </span>
                </div>
              );
            })}
          </div>
        </GlassPanel>
      </div>

      <ActiveAgents />
    </CommandShell>
  );
}