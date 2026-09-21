'use client';

import React from 'react';
import styles from '@/components/command/heroWorkflow.module.css';
import { CommandShell } from '@/components/command/CommandShell';
import { PageHeader } from '@/components/command/HeroWorkflow';
import { AICore } from '@/components/core/AICore';
import { CodeAnalysis } from '@/components/panels/CodeAnalysis';
import { ActiveAgents } from '@/components/panels/SystemHealth';
import { GlassPanel } from '@/components/hud/hud';

export default function ReasoningPage() {
  return (
    <CommandShell>
      <PageHeader eyebrow="TRANSPARENT INTELLIGENCE" title="AI REASONING" icon="brain">
        Auditable, step-by-step rationale behind every finding — no black-box verdicts.
      </PageHeader>

      <div className={styles.grid2}>
        <AICore />
        <GlassPanel title="Decision Doctrine" icon="brain" accent="violet">
          <ul style={{ display: 'flex', flexDirection: 'column', gap: 12, listStyle: 'none' }}>
            {[
              ['DETECT', 'Span hallucination, security and dependency patterns in one pass', 'var(--red)'],
              ['TRACE', 'Pinpoint the exact file, line and reasoning for each finding', 'var(--amber)'],
              ['VALIDATE', 'Score every claim with a calibrated confidence vector', 'var(--cyan)'],
              ['PROVENANCE', 'Every verdict links to the source lines it was derived from', 'var(--violet)'],
            ].map(([step, desc, color]) => (
              <li key={step} style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 10, fontWeight: 800, letterSpacing: '0.08em', color, border: `1px solid ${color}`, borderRadius: 6, padding: '3px 7px', whiteSpace: 'nowrap' }}>
                  {step}
                </span>
                <span style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.55 }}>{desc}</span>
              </li>
            ))}
          </ul>
        </GlassPanel>
      </div>

      <CodeAnalysis />
      <ActiveAgents />
    </CommandShell>
  );
}