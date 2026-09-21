'use client';

import React from 'react';
import styles from './heroWorkflow.module.css';
import { CommandShell } from './CommandShell';
import { WelcomeHero, ScanWorkflow } from './HeroWorkflow';
import { AICore } from '@/components/core/AICore';
import { ThreatIntelligence } from '@/components/panels/ThreatIntelligence';
import { CodeAnalysis } from '@/components/panels/CodeAnalysis';
import { SystemLogs } from '@/components/panels/SystemLogs';
import { SecurityPipeline } from '@/components/panels/SecurityPipeline';
import { ThreatVisualization } from '@/components/panels/ThreatVisualization';
import { NetworkTopology } from '@/components/panels/NetworkTopology';
import { SystemHealth, ActiveAgents } from '@/components/panels/SystemHealth';
import { ConfidenceMetrics } from '@/components/panels/ConfidenceMetrics';

export default function CommandCenter() {
  return (
    <CommandShell>
      <WelcomeHero />

      <div className={styles.dashGrid}>
        <div className={styles.dashCol}>
          <ThreatIntelligence />
          <ActiveAgents />
          <NetworkTopology />
        </div>

        <div className={styles.dashCol}>
          <AICore />
          <ConfidenceMetrics />
          <SystemLogs />
        </div>

        <div className={styles.dashCol}>
          <CodeAnalysis />
          <SystemHealth />
        </div>
      </div>

      <ScanWorkflow />

      <div className={styles.wideRow}>
        <ThreatVisualization />
        <SecurityPipeline />
      </div>
    </CommandShell>
  );
}