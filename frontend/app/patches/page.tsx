'use client';

import React from 'react';
import styles from '@/components/command/heroWorkflow.module.css';
import pstyles from '@/components/panels/panels.module.css';
import { CommandShell } from '@/components/command/CommandShell';
import { PageHeader } from '@/components/command/HeroWorkflow';
import { GlassPanel } from '@/components/hud/hud';
import { useCommandCenter } from '@/components/command/CommandCenterContext';
import { Icon } from '@/components/icons';
import { ConfidenceMetrics } from '@/components/panels/ConfidenceMetrics';
import { SecurityPipeline } from '@/components/panels/SecurityPipeline';

const PATCH_DOCTRINE = [
  { label: 'STRATEGY', value: 'Contextual multi-patch generation', color: 'var(--green)' },
  { label: 'VALIDATION', value: 'Sandboxed execution + regression', color: 'var(--cyan)' },
  { label: 'GATING', value: 'Confidence-weighted patch release', color: 'var(--violet)' },
  { label: 'LEARNING', value: 'Outcome feedback into ACE', color: 'var(--magenta)' },
];

export default function PatchesPage() {
  const ctx = useCommandCenter();
  const patches = ctx.patches ?? [];

  return (
    <CommandShell>
      <PageHeader eyebrow="REPAIR ORCHESTRATION" title="PATCH INTELLIGENCE" icon="wrench">
        Confidence-gated remediation produced by the patch generation agent and validated before release.
      </PageHeader>

      <div className={styles.grid2}>
        <GlassPanel title="Patch Doctrine" icon="wrench" accent="green">
          <div className={pstyles.summaryChips}>
            {PATCH_DOCTRINE.map((d) => (
              <div className={pstyles.summaryChip} key={d.label}>
                <span className={pstyles.summaryChipValue} style={{ color: d.color, fontSize: 11 }}>{d.label}</span>
                <span className={pstyles.summaryChipLabel}>{d.value}</span>
              </div>
            ))}
          </div>
        </GlassPanel>
        <ConfidenceMetrics />
      </div>

      <SecurityPipeline />

      <GlassPanel
        title="Generated Patch Queue"
        icon="flask"
        live={patches.length > 0}
        liveLabel={patches.length ? `${patches.length} PATCHES` : 'IDLE'}
        accent="green"
      >
        {patches.length === 0 && (
          <div className={pstyles.emptyBox}>
            <Icon name="flask" size={22} />
            No patches generated yet. Complete a scan to surface validated patch candidates from the REPAIR stage.
          </div>
        )}

        {patches.length > 0 && (
          <div className={styles.pageStack}>
            {patches.map((p, i) => (
              <div className={pstyles.patchCard} key={`${p.patch_id ?? i}-${i}`}>
                <div className={pstyles.patchTop}>
                  <span className={pstyles.patchId}>
                    <Icon name="flask" size={12} /> {p.patch_id ?? `PATCH-${i + 1}`}
                  </span>
                  <span className={pstyles.patchVuln}>TARGETS {p.vulnerability_id ?? '—'}</span>
                </div>
                <div className={pstyles.patchMeta}>
                  <span>STRATEGY · {(p.patch_strategy ?? 'contextual').toUpperCase()}</span>
                  <span>STATUS · {p.status ?? 'generated'}</span>
                  <span>CONFIDENCE · {p.confidence !== undefined ? `${(p.confidence * 100).toFixed(1)}%` : '—'}</span>
                </div>
                <p className={pstyles.patchDesc}>{p.description ?? 'Validated patch candidate awaiting the confidence gate.'}</p>
              </div>
            ))}
          </div>
        )}
      </GlassPanel>
    </CommandShell>
  );
}