'use client';

import React from 'react';
import styles from '@/components/command/heroWorkflow.module.css';
import { CommandShell } from '@/components/command/CommandShell';
import { PageHeader } from '@/components/command/HeroWorkflow';
import { SystemHealth } from '@/components/panels/SystemHealth';
import { SystemLogs } from '@/components/panels/SystemLogs';
import { ThreatVisualization } from '@/components/panels/ThreatVisualization';
import { NetworkTopology } from '@/components/panels/NetworkTopology';

export default function RuntimePage() {
  return (
    <CommandShell>
      <PageHeader eyebrow="PRODUCTION TELEMETRY" title="RUNTIME DEFENSE" icon="zap">
        Continuous guardrails watching live traffic, adversarial activity and anomaly endpoints.
      </PageHeader>

      <div className={styles.wideRow}>
        <SystemLogs />
        <SystemHealth />
      </div>

      <div className={styles.wideRow}>
        <ThreatVisualization />
        <NetworkTopology />
      </div>
    </CommandShell>
  );
}