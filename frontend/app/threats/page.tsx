'use client';

import React from 'react';
import styles from '@/components/command/heroWorkflow.module.css';
import { CommandShell } from '@/components/command/CommandShell';
import { PageHeader } from '@/components/command/HeroWorkflow';
import { ThreatIntelligence } from '@/components/panels/ThreatIntelligence';
import { ThreatVisualization } from '@/components/panels/ThreatVisualization';
import { NetworkTopology } from '@/components/panels/NetworkTopology';
import { ActiveAgents } from '@/components/panels/SystemHealth';
import { SystemLogs } from '@/components/panels/SystemLogs';

export default function ThreatsPage() {
  return (
    <CommandShell>
      <PageHeader eyebrow="LIVE INTELLIGENCE" title="THREAT INTELLIGENCE" icon="activity">
        Real-time alert correlation from the runtime monitoring engine across the security fabric.
      </PageHeader>

      <div className={styles.grid2}>
        <div className={styles.pageStack}>
          <ThreatIntelligence />
          <NetworkTopology />
        </div>
        <div className={styles.pageStack}>
          <ThreatVisualization />
          <SystemLogs />
        </div>
      </div>

      <ActiveAgents />
    </CommandShell>
  );
}