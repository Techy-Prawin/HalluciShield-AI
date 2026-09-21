'use client';

import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import {
  fetchBackendHealth,
  fetchAiHealth,
  fetchMonitoringSummary,
  fetchMonitoringAlerts,
  fetchMonitoringEvents,
  fetchLearningSummary,
  startScan,
  fetchScanStatus,
  fetchScanFindings,
  fetchScanPatches,
  downloadSecuredFile,
  type MonitoringSummary,
  type HealthInfo,
  type AlertRecord,
  type RuntimeEventRecord,
  type LearningSummary,
  type ScanStatusPayload,
  type FindingsPayload,
  type PatchRecord,
} from '@/lib/api';

interface CommandCenterState {
  backendHealth: HealthInfo | null;
  aiHealth: HealthInfo | null;
  monitoring: MonitoringSummary | null;
  alerts: AlertRecord[];
  events: RuntimeEventRecord[];
  learningSummary: LearningSummary | null;
  scan: ScanStatusPayload | null;
  findings: FindingsPayload | null;
  patches: PatchRecord[];
  scanPolling: boolean;
  scanError: string | null;
  downloadState: { busy: boolean; error: string | null };
  startScanFlow: (_repositoryId: string) => Promise<string | null>;
  downloadSecuredFile: (_repositoryId: string, _scanId: string) => Promise<{ ok: boolean; fileName?: string; error?: string }>;
  resetScan: () => void;
  isConnecting: boolean;
  lastSync: string | null;
  refresh: () => Promise<void>;
}

const TERMINAL_SCAN_STATES = ['COMPLETED', 'FAILED'];

const CommandCenterContext = createContext<CommandCenterState | null>(null);

export function useCommandCenter(): CommandCenterState {
  const ctx = useContext(CommandCenterContext);
  if (!ctx) throw new Error('useCommandCenter must be used within CommandCenterProvider');
  return ctx;
}

export function CommandCenterProvider({ children }: { children: React.ReactNode }) {
  const [backendHealth, setBackendHealth] = useState<HealthInfo | null>(null);
  const [aiHealth, setAiHealth] = useState<HealthInfo | null>(null);
  const [monitoring, setMonitoring] = useState<MonitoringSummary | null>(null);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [events, setEvents] = useState<RuntimeEventRecord[]>([]);
  const [learningSummary, setLearningSummary] = useState<LearningSummary | null>(null);
  const [scan, setScan] = useState<ScanStatusPayload | null>(null);
  const [findings, setFindings] = useState<FindingsPayload | null>(null);
  const [patches, setPatches] = useState<PatchRecord[]>([]);
  const [scanPolling, setScanPolling] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [downloadState, setDownloadState] = useState<{ busy: boolean; error: string | null }>({ busy: false, error: null });
  const [isConnecting, setIsConnecting] = useState(true);
  const [lastSync, setLastSync] = useState<string | null>(null);
  const scanTimer = useRef<number | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [b, a, m, al, ev, lr] = await Promise.all([
        fetchBackendHealth(),
        fetchAiHealth(),
        fetchMonitoringSummary(),
        fetchMonitoringAlerts(),
        fetchMonitoringEvents(),
        fetchLearningSummary(),
      ]);
      setBackendHealth(b);
      setAiHealth(a);
      setMonitoring(m);
      setAlerts(al);
      setEvents(ev);
      setLearningSummary(lr);
    } catch {
      /* individual fetches already swallow errors */
    } finally {
      setIsConnecting(false);
      setLastSync(new Date().toISOString());
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 12_000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    return () => {
      if (scanTimer.current !== null) window.clearInterval(scanTimer.current);
    };
  }, []);

  const startScanFlow = useCallback(async (repositoryId: string): Promise<string | null> => {
    // Reset any previous polling.
    if (scanTimer.current !== null) window.clearInterval(scanTimer.current);
    setScanError(null);

    const started = await startScan(repositoryId);
    if (!started?.scanId) {
      setScanError(started?.error || 'The scan could not be started.');
      return null;
    }

    setScan({ ...started, repositoryId });
    setFindings(null);
    setPatches([]);
    setScanPolling(true);

    const poll = async () => {
      if (!started.scanId) return;
      const status = await fetchScanStatus(repositoryId, started.scanId);
      if (!status || !status.status) return;
      setScan(status);

      if (TERMINAL_SCAN_STATES.includes(status.status)) {
        if (scanTimer.current !== null) window.clearInterval(scanTimer.current);
        scanTimer.current = null;
        setScanPolling(false);
        try {
          const [f, p] = await Promise.all([
            fetchScanFindings(repositoryId, started.scanId),
            fetchScanPatches(repositoryId, started.scanId),
          ]);
          setFindings(f);
          setPatches(p);
        } catch {
          // Non-critical background findings fetch
        }
      }
    };

    scanTimer.current = window.setInterval(() => {
      void poll();
    }, 2000);
    void poll();

    return started.scanId;
  }, []);

  const resetScan = useCallback(() => {
    if (scanTimer.current !== null) window.clearInterval(scanTimer.current);
    scanTimer.current = null;
    setScan(null);
    setFindings(null);
    setPatches([]);
    setScanPolling(false);
    setScanError(null);
    setDownloadState({ busy: false, error: null });
  }, []);

  const downloadForScan = useCallback(
    async (repositoryId: string, scanId: string): Promise<{ ok: boolean; fileName?: string; error?: string }> => {
      setDownloadState((s) => ({ ...s, busy: true, error: null }));
      const result = await downloadSecuredFile(repositoryId, scanId);
      setDownloadState((s) => ({ ...s, busy: false, error: result.ok ? null : result.error ?? 'Download failed.' }));
      return result;
    },
    []
  );

  const value: CommandCenterState = {
    backendHealth,
    aiHealth,
    monitoring,
    alerts,
    events,
    learningSummary,
    scan,
    findings,
    patches,
    scanPolling,
    scanError,
    downloadState,
    startScanFlow,
    downloadSecuredFile: downloadForScan,
    resetScan,
    isConnecting,
    lastSync,
    refresh,
  };

  return <CommandCenterContext.Provider value={value}>{children}</CommandCenterContext.Provider>;
}

/** Small hook to keep components out of the tree when provider is missing (tests). */
export function useOptionalCommandCenter(): CommandCenterState | null {
  return useContext(CommandCenterContext);
}