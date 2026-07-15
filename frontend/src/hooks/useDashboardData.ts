import { useCallback, useEffect, useRef, useState } from 'react';

import {
  eventSource,
  fetchAlerts,
  fetchAnalysisRuns,
  fetchIncidents,
  type AlertFilters as AlertQueryFilters,
  type IncidentFilters as IncidentQueryFilters,
  type IncidentView,
} from '../api';
import { AlertRecord, AnalysisProgressEntry, AnalysisRun, Incident, PageInfo } from '../types';
import {
  appendProgress,
  clearProgress,
  parseRealtimeEvent,
  RealtimeEventPayload,
  resetProgress,
  updateCompletedProgressRuns,
} from '../utils/realtime';
import { emptyPage, pageRequest } from '../utils/pagination';

export type DashboardPageIndexes = {
  incidents: number;
  alerts: number;
  analysis: number;
};

export function useDashboardData(
  pageIndexes: DashboardPageIndexes,
  incidentView: IncidentView,
  incidentFilters: IncidentQueryFilters,
  alertFilters: AlertQueryFilters,
) {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [analysisRuns, setAnalysisRuns] = useState<AnalysisRun[]>([]);
  const [incidentPage, setIncidentPage] = useState<PageInfo>(() => emptyPage());
  const [alertPage, setAlertPage] = useState<PageInfo>(() => emptyPage());
  const [analysisPage, setAnalysisPage] = useState<PageInfo>(() => emptyPage());
  const [progressByRun, setProgressByRun] = useState<Record<string, AnalysisProgressEntry[]>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [realtimePayload, setRealtimePayload] = useState<RealtimeEventPayload>();
  const realtimeRefreshTimerRef = useRef<number | null>(null);
  const completedProgressRunsRef = useRef(new Set<string>());

  const load = useCallback(async (options: { silent?: boolean } = {}) => {
    let analysisLoaded = false;
    if (!options.silent) {
      setLoading(true);
    }
    setError('');
    try {
      const [incidentData, alertData] = await Promise.all([
        fetchIncidents(pageRequest(pageIndexes.incidents), incidentView, incidentFilters),
        fetchAlerts(pageRequest(pageIndexes.alerts), alertFilters),
      ]);
      setIncidents(incidentData.items);
      setIncidentPage(incidentData.page);
      setAlerts(alertData.items);
      setAlertPage(alertData.page);
      try {
        const nextAnalysisRuns = await fetchAnalysisRuns(pageRequest(pageIndexes.analysis));
        setAnalysisRuns(nextAnalysisRuns.items);
        setAnalysisPage(nextAnalysisRuns.page);
        analysisLoaded = true;
      } catch (err) {
        setAnalysisRuns([]);
        setAnalysisPage(emptyPage(pageIndexes.analysis));
        const message = err instanceof Error ? err.message : 'Failed to load analysis runs.';
        setError(`Analysis runs are unavailable: ${message}`);
      }
    } catch (err) {
      setIncidents([]);
      setAlerts([]);
      setAnalysisRuns([]);
      setIncidentPage(emptyPage(pageIndexes.incidents));
      setAlertPage(emptyPage(pageIndexes.alerts));
      setAnalysisPage(emptyPage(pageIndexes.analysis));
      const message = err instanceof Error ? err.message : 'Failed to load dashboard data.';
      setError(message);
    } finally {
      if (!options.silent) {
        setLoading(false);
      }
    }
    return analysisLoaded;
  }, [alertFilters, incidentFilters, incidentView, pageIndexes.alerts, pageIndexes.analysis, pageIndexes.incidents]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    let source: EventSource;
    try {
      source = eventSource();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Realtime updates are unavailable.';
      setError(`Realtime updates are unavailable: ${message}`);
      return undefined;
    }
    const handleRealtimeEvent = (event: Event) => {
      const payload = parseRealtimeEvent(event);
      setRealtimePayload(payload);
      if (realtimeRefreshTimerRef.current !== null) {
        window.clearTimeout(realtimeRefreshTimerRef.current);
      }
      realtimeRefreshTimerRef.current = window.setTimeout(async () => {
        realtimeRefreshTimerRef.current = null;
        const analysisLoaded = await load({ silent: true });
        if (!analysisLoaded) return;
        const completedRunIDs = [...completedProgressRunsRef.current];
        if (completedRunIDs.length > 0) {
          setProgressByRun((current) => clearProgress(current, completedRunIDs));
          completedProgressRunsRef.current.clear();
        }
      }, 750);
    };
    const handleProgressEvent = (event: Event) => {
      const payload = parseRealtimeEvent(event);
      setProgressByRun((current) => appendProgress(current, payload));
    };
    const handleStartedEvent = (event: Event) => {
      const payload = parseRealtimeEvent(event);
      completedProgressRunsRef.current = updateCompletedProgressRuns(completedProgressRunsRef.current, payload);
      setProgressByRun((current) => resetProgress(current, payload));
      handleRealtimeEvent(event);
    };
    const handleCompletedEvent = (event: Event) => {
      const payload = parseRealtimeEvent(event);
      completedProgressRunsRef.current = updateCompletedProgressRuns(completedProgressRunsRef.current, payload);
      handleRealtimeEvent(event);
    };
    source.onmessage = handleRealtimeEvent;
    source.addEventListener('alert.created', handleRealtimeEvent);
    source.addEventListener('analysis.started', handleStartedEvent);
    source.addEventListener('analysis.progress', handleProgressEvent);
    source.addEventListener('analysis.completed', handleCompletedEvent);
    source.addEventListener('incident.resolved', handleRealtimeEvent);
    source.addEventListener('incident.updated', handleRealtimeEvent);
    source.addEventListener('feedback.updated', handleRealtimeEvent);
    return () => {
      source.close();
      if (realtimeRefreshTimerRef.current !== null) {
        window.clearTimeout(realtimeRefreshTimerRef.current);
      }
    };
  }, [load]);

  return {
    incidents,
    alerts,
    analysisRuns,
    incidentPage,
    alertPage,
    analysisPage,
    loading,
    error,
    load,
    realtimePayload,
    progressByRun,
  };
}
