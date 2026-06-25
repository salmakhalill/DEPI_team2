import { useEffect, useRef, useState, useCallback } from 'react';
import { WS_URL } from '../api/client';
import type { ScanPhase, ScanStatus, ScanState } from '../types/scan';
import { detectPhase, phaseToProgress, buildActivity, buildFinding, buildEndpoint, resetParser } from '../engine/messageParser';

const INITIAL_STATE: Omit<ScanState, 'scanId' | 'targetUrl'> = {
  status: 'connecting',
  currentPhase: 1,
  completedPhases: new Set<ScanPhase>(),
  connected: false,
  elapsedSec: 0,
  scanProgress: 3,
  endpoints: [],
  findings: [],
  activityFeed: [],
  reportReady: false,
};

export function useScanWebSocket(scanId: string | undefined) {
  const [state, setState] = useState<ScanState>({
    ...INITIAL_STATE,
    scanId: scanId || '',
    targetUrl: '',
  });

  const wsRef     = useRef<WebSocket | null>(null);
  const startTime = useRef<number>(Date.now());
  const timerRef  = useRef<ReturnType<typeof setInterval> | null>(null);
  const statusRef = useRef<ScanStatus>('connecting');

  // keep ref in sync for use inside ws callbacks
  useEffect(() => { statusRef.current = state.status; }, [state.status]);

  // elapsed timer
  useEffect(() => {
    timerRef.current = setInterval(() => {
      setState(s => ({ ...s, elapsedSec: Math.floor((Date.now() - startTime.current) / 1000) }));
    }, 1000);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, []);

  const connect = useCallback(() => {
    if (!scanId) return;
    resetParser();
    startTime.current = Date.now();

    const ws = new WebSocket(WS_URL(scanId));
    wsRef.current = ws;

    ws.onopen = () => {
      setState(s => ({ ...s, connected: true, status: 'running', currentPhase: 1, scanProgress: 5 }));
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        const msg: string = data.message || '';
        if (!msg.trim()) return;

        setState(prev => {
          const newPhase   = detectPhase(msg);
          let currentPhase = prev.currentPhase;
          let completedPhases = new Set(prev.completedPhases);

          // Phase transition
          if (newPhase !== null && newPhase !== currentPhase) {
            if (newPhase > currentPhase) {
              for (let i = prev.currentPhase as number; i < newPhase; i++) {
                completedPhases.add(i as ScanPhase);
              }
            }
            currentPhase = newPhase;
          }

          const scanProgress = Math.max(prev.scanProgress, phaseToProgress(currentPhase));
          const activity     = buildActivity(msg, currentPhase);
          const finding      = buildFinding(msg);
          const endpoint     = buildEndpoint(msg);

          // Mark endpoint as vulnerable if we already have a finding for it
          let endpoints = [...prev.endpoints];
          if (endpoint) {
            const exists = endpoints.some(e => e.path === endpoint.path);
            if (!exists) endpoints = [...endpoints, endpoint];
          }
          if (finding) {
            endpoints = endpoints.map(e =>
              e.path === finding.endpoint ? { ...e, scanned: true, vulnerable: true } : e
            );
          }

          const isCompleted = currentPhase === 8 ||
            msg.toLowerCase().includes('completed successfully') ||
            msg.toLowerCase().includes('[done]');

          if (isCompleted) {
            completedPhases = new Set([1,2,3,4,5,6,7,8] as ScanPhase[]);
            if (timerRef.current) clearInterval(timerRef.current);
          }

          return {
            ...prev,
            currentPhase,
            completedPhases,
            scanProgress: isCompleted ? 100 : scanProgress,
            activityFeed: [activity, ...prev.activityFeed].slice(0, 200),
            findings:     finding ? [...prev.findings, finding] : prev.findings,
            endpoints,
            status:       isCompleted ? 'completed'
                        : msg.includes('[ERROR]') ? 'failed'
                        : prev.status,
            reportReady: isCompleted,
          };
        });

      } catch { /* ignore bad JSON */ }
    };

    ws.onclose = () => {
      setState(s => ({
        ...s,
        connected: false,
        status: statusRef.current === 'completed' || statusRef.current === 'failed'
          ? statusRef.current : 'connecting',
      }));
    };

    ws.onerror = () => {
      setState(s => ({ ...s, status: 'failed', connected: false }));
    };

  }, [scanId]);

  useEffect(() => {
    connect();
    return () => { wsRef.current?.close(); };
  }, [connect]);

  const reconnect = useCallback(() => {
    wsRef.current?.close();
    setState(s => ({ ...s, status: 'connecting' }));
    setTimeout(connect, 600);
  }, [connect]);

  return { state, reconnect };
}
