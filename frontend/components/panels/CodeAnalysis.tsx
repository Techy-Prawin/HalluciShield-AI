'use client';

import React from 'react';
import styles from './panels.module.css';
import { GlassPanel } from '@/components/hud/hud';
import { Icon } from '@/components/icons';
import { useOptionalCommandCenter } from '@/components/command/CommandCenterContext';
import { extractFindings } from '@/lib/api';
import { severityMeta } from '@/lib/hud';

type Tok = { type: string; value: string };

function tokenize(line: string): Tok[] {
  const tokens: Tok[] = [];
  const regex =
    /(\bdef\b|\breturn\b|\bimport\b|\bfrom\b)|("[^"]*"|'[^']*')|(\b\w+\b(?=\())|([A-Za-z_]\w*)|(\+)|(\d+)|(#{1}.+)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(line)) !== null) {
    if (m.index > last) tokens.push({ type: 'txt', value: line.slice(last, m.index) });
    if (m[1]) tokens.push({ type: 'kw', value: m[1] });
    else if (m[2]) tokens.push({ type: 'str', value: m[2] });
    else if (m[3]) tokens.push({ type: 'fn', value: m[3] });
    else if (m[4]) tokens.push({ type: 'txt', value: m[4] });
    else if (m[5]) tokens.push({ type: 'op', value: m[5] });
    else if (m[6]) tokens.push({ type: 'num', value: m[6] });
    else if (m[7]) tokens.push({ type: 'cmt', value: m[7] });
    last = regex.lastIndex;
  }
  if (last < line.length) tokens.push({ type: 'txt', value: line.slice(last) });
  return tokens;
}

function renderTokens(line: string): React.ReactNode {
  return tokenize(line).map((t, i) =>
    t.type === 'txt' ? (
      <React.Fragment key={i}>{t.value}</React.Fragment>
    ) : (
      <span key={i} className={styles[`tk-${t.type}`]}>
        {t.value}
      </span>
    )
  );
}

export function CodeAnalysis() {
  const ctx = useOptionalCommandCenter();
  const scan = ctx?.scan;
  const findings = ctx?.findings;
  const securityFindings = findings ? extractFindings(findings.securityFindings) : [];
  const finding = securityFindings[0] as Record<string, unknown> | undefined;

  const displayName = (leaf: unknown): string =>
    typeof leaf === 'string' ? leaf.split('/').pop() ?? leaf : 'source';

  const fileName = displayName(finding?.file_path ?? finding?.file ?? finding?.snippet ?? 'source');
  const snippet =
    typeof finding?.code_snippet === 'string'
      ? finding.code_snippet
      : typeof finding?.snippet === 'string'
        ? finding.snippet
        : null;
  const lineNumber =
    typeof finding?.line_number === 'number' ? finding.line_number : typeof finding?.line === 'number' ? finding.line : null;
  const title = typeof finding?.vulnerability_type === 'string' ? finding.vulnerability_type : 'Security Finding';
  const cwe = typeof finding?.cwe_id === 'string' ? finding.cwe_id : null;
  const sev = severityMeta(typeof finding?.severity === 'string' ? finding.severity : 'medium');
  const description =
    typeof finding?.description === 'string'
      ? finding.description
      : typeof finding?.reasoning === 'string'
        ? finding.reasoning
        : typeof finding?.evidence === 'string'
          ? finding.evidence
          : null;
  const evidence = typeof finding?.evidence === 'string' ? finding.evidence : null;

  const snippetLines = snippet ? snippet.split('\n') : [];
  const vulnLineIndex = lineNumber !== null && snippetLines.length > 0 ? Math.max(0, lineNumber - 1) : -1;

  const patch = ctx?.patches?.find((p) => p.status === 'APPLIED' || p.status === 'SUCCESS') ?? ctx?.patches?.[0];

  return (
    <GlassPanel
      title="Code Analysis"
      icon="code"
      live={!!ctx && securityFindings.length > 0}
      liveLabel={ctx ? (scan?.status ?? 'Idle') : 'Offline'}
      accent="blue"
      scrollable={false}
    >
      {!finding ? (
        <div className={styles.emptyBox} style={{ padding: 18 }}>
          <Icon name="shield" size={22} style={{ color: 'var(--green)' }} />
          <span>
            {ctx
              ? 'No security findings in the latest scan — the analyzed code is clean.'
              : 'No scan connected. Trigger a scan to analyze real code findings.'}
          </span>
        </div>
      ) : (
        <div className={styles.codeLayout}>
          <div>
            <div className={styles.codeFileBar}>
              <span className={styles.codeFileName}>
                <Icon name="folder" size={12} style={{ color: 'var(--sky)' }} />
                {fileName}
              </span>
              <span className={styles.codeFileBadge}>{cwe ?? 'REPORTED'}</span>
            </div>
            <div className={styles.codePre}>
              <div className={styles.codeScroll}>
                {snippetLines.length > 0 ? (
                  snippetLines.map((line, i) => (
                    <div className={styles.codeLine} key={i}>
                      <span className={styles.codeNum}>{lineNumber !== null ? lineNumber + i : i + 1}</span>
                      <span className={`${styles.codeSrc} ${i === vulnLineIndex ? styles.codeVuln : ''}`}>
                        {renderTokens(line)}
                        {i === vulnLineIndex && (
                          <span className={styles.vulnMarker}>
                            <Icon name="alert" size={9} /> {cwe ?? 'REPORTED'}
                          </span>
                        )}
                      </span>
                    </div>
                  ))
                ) : (
                  <div className={styles.codeLine}>
                    <span className={styles.codeNum}>—</span>
                    <span className={styles.codeSrc}>{fileName} (no snippet supplied by backend)</span>
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className={styles.reasonCol}>
            <div className={styles.reasonTitle}>
              <Icon name="brain" size={13} style={{ color: 'var(--cyan)' }} />
              AI Reasoning
              <span className={styles.reasonTitleBar} />
            </div>

            <div className={styles.findingBadge}>
              <Icon name="alert" size={15} style={{ color: sev.color }} />
              <span className={styles.findingCWE}>{title}</span>
              <span className={styles.findingSev} style={{ color: sev.color, borderColor: sev.color }}>
                {sev.label.toUpperCase()}
              </span>
            </div>

            {description && <ReasonCard label="Observation" value={description} />}
            {evidence && <ReasonCard label="Evidence" value={evidence} />}
            {typeof finding?.recommendation === 'string' && <ReasonCard label="Recommended Action" value={finding.recommendation} />}

            <div className={styles.confLine}>
              <Icon name="gauge" size={15} style={{ color: 'var(--violet)' }} />
              <span className={styles.confBar}>
                <span
                  className={styles.confBarFill}
                  style={{ width: typeof scan?.confidence === 'number' ? `${Math.min(100, Math.max(0, scan.confidence))}%` : '0%' }}
                />
              </span>
              <span className="mono" style={{ color: 'var(--violet)', fontSize: 12, fontWeight: 700 }}>
                {typeof scan?.confidence === 'number' ? `${scan.confidence}%` : '—'}
              </span>
            </div>
            <div className={styles.reasonCardValue} style={{ fontSize: 9.5, color: 'var(--text-3)' }}>
              Scan confidence as reported by the backend pipeline.
            </div>

            {patch && (
              <div className={styles.reasonCard} style={{ marginTop: 8 }}>
                <span className={styles.reasonCardLabel}>BACKEND PATCH · {patch.patch_strategy ?? (patch.status ?? 'GENERATED')}</span>
                <span className={styles.reasonCardValue}>
                  {typeof patch.modified_code === 'string' ? patch.modified_code : (patch.description ?? 'Patch proposed by the pipeline.')}
                </span>
              </div>
            )}
          </div>
        </div>
      )}
    </GlassPanel>
  );
}

function ReasonCard({ label, value }: { label: string; value: string }) {
  return (
    <div className={styles.reasonCard}>
      <span className={styles.reasonCardLabel}>{label}</span>
      <span className={styles.reasonCardValue}>{value}</span>
    </div>
  );
}