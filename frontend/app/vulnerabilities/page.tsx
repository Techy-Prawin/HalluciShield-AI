'use client';

import React from 'react';
import styles from '@/components/command/heroWorkflow.module.css';
import pstyles from '@/components/panels/panels.module.css';
import { CommandShell } from '@/components/command/CommandShell';
import { PageHeader } from '@/components/command/HeroWorkflow';
import { GlassPanel } from '@/components/hud/hud';
import { useCommandCenter } from '@/components/command/CommandCenterContext';
import { Icon } from '@/components/icons';
import { CodeAnalysis } from '@/components/panels/CodeAnalysis';
import { SecurityPipeline } from '@/components/panels/SecurityPipeline';
import { severityMeta } from '@/lib/hud';

type Finding = Record<string, unknown>;

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function stringOf(value: unknown): string {
  return typeof value === 'string' ? value : value === undefined || value === null ? '—' : String(value);
}

function FindingsRegistry() {
  const ctx = useCommandCenter();
  const findings = ctx.findings;
  const flat: Finding[] = findings
    ? [
        ...asArray(findings.hallucinationFindings),
        ...asArray(findings.securityFindings),
        ...asArray(findings.dependencyFindings),
      ].map((f) => f as Finding)
    : [];

  const counts = {
    hallucination: findings ? asArray(findings.hallucinationFindings).length : 0,
    security: findings ? asArray(findings.securityFindings).length : 0,
    dependency: findings ? asArray(findings.dependencyFindings).length : 0,
  };

  return (
    <GlassPanel title="Vulnerability Registry" live={flat.length > 0} liveLabel={flat.length ? `${flat.length} ENTRIES` : 'IDLE'} icon="bug" accent="red" scrollable>
      {findings === null && (
        <div className={pstyles.emptyBox}>
          <Icon name="bug" size={22} />
          No scan executed yet. Ingest a repository in the Command Center to populate the vulnerability registry with real findings.
        </div>
      )}

      {findings && flat.length === 0 && (
        <div className={pstyles.emptyBox} style={{ borderColor: 'rgba(52,211,153,0.4)' }}>
          <Icon name="check" size={22} style={{ color: 'var(--green)' }} />
          Scan complete — zero findings recorded across hallucination, security and dependency stages.
        </div>
      )}

      {findings !== null && (
        <div className={pstyles.summaryChips}>
          <div className={pstyles.summaryChip}>
            <span className={pstyles.summaryChipValue} style={{ color: 'var(--magenta)' }}>{counts.hallucination}</span>
            <span className={pstyles.summaryChipLabel}>HALLUCINATION</span>
          </div>
          <div className={pstyles.summaryChip}>
            <span className={pstyles.summaryChipValue} style={{ color: 'var(--red)' }}>{counts.security}</span>
            <span className={pstyles.summaryChipLabel}>SECURITY</span>
          </div>
          <div className={pstyles.summaryChip}>
            <span className={pstyles.summaryChipValue} style={{ color: 'var(--sky)' }}>{counts.dependency}</span>
            <span className={pstyles.summaryChipLabel}>DEPENDENCY</span>
          </div>
        </div>
      )}

      {flat.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table className={pstyles.regTable}>
            <thead>
              <tr>
                <th>ID</th>
                <th>Severity</th>
                <th>File</th>
                <th>Line</th>
                <th>Message</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {flat.map((f, i) => {
                const sev = severityMeta(stringOf(f.severity));
                const id = stringOf(f.id ?? f.rule_id ?? f.cwe ?? f.vulnerability_type ?? f.type);
                return (
                  <tr key={`${id}-${i}`}>
                    <td className={pstyles.regCode}>{id || `F-${i + 1}`}</td>
                    <td>
                      <span className={pstyles.regBadge} style={{ color: sev.color, border: `1px solid ${sev.color}`, background: `${sev.color}14` }}>
                        {sev.label.toUpperCase()}
                      </span>
                    </td>
                    <td className={pstyles.regFile} title={stringOf(f.file ?? f.path ?? f.language)}>
                      {stringOf(f.file ?? f.path ?? '—')}
                    </td>
                    <td>{stringOf(f.line ?? f.start_line ?? '—')}</td>
                    <td className={pstyles.regMsg} title={stringOf(f.message ?? f.description ?? f.reasoning)}>
                      {stringOf(f.message ?? f.description ?? f.reasoning ?? '—')}
                    </td>
                    <td>{stringOf(f.status ?? '—')}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </GlassPanel>
  );
}

export default function VulnerabilitiesPage() {
  return (
    <CommandShell>
      <PageHeader eyebrow="DETECT &amp; CLASSIFY" title="VULNERABILITIES" icon="bug">
        Per-repository vulnerability intelligence produced by the hallucination, security and dependency agents.
      </PageHeader>

      <div className={styles.wideRow}>
        <CodeAnalysis />
        <SecurityPipeline />
      </div>

      <FindingsRegistry />
    </CommandShell>
  );
}