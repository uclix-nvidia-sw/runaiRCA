import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

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
  const [incidentsLoading, setIncidentsLoading] = useState(true);
  const [alertsLoading, setAlertsLoading] = useState(true);
  const [analysisLoading, setAnalysisLoading] = useState(true);
  const [incidentsError, setIncidentsError] = useState('');
  const [alertsError, setAlertsError] = useState('');
  const [analysisError, setAnalysisError] = useState('');
  const [realtimeError, setRealtimeError] = useState('');
  const [realtimePayload, setRealtimePayload] = useState<RealtimeEventPayload>();
  const realtimeRefreshTimerRef = useRef<number | null>(null);
  const completedProgressRunsRef = useRef(new Set<string>());
  const incidentsVersionRef = useRef(0);
  const alertsVersionRef = useRef(0);
  const analysisVersionRef = useRef(0);

  // Each list loads independently so a page flip on one table never refetches
  // the other two. Overlapping loads (mount + SSE refresh + filter change) can
  // resolve out of order; per-list version refs make sure only the latest
  // invocation touches state, and a failed silent refresh must not wipe data
  // that is already on screen.
  const loadIncidents = useCallback(async (options: { silent?: boolean } = {}) => {
    const version = ++incidentsVersionRef.current;
    const isCurrent = () => version === incidentsVersionRef.current;
    if (!options.silent) {
      setIncidentsLoading(true);
    }
    setIncidentsError('');
    try {
      const data = await fetchIncidents(pageRequest(pageIndexes.incidents), incidentView, incidentFilters);
      if (!isCurrent()) return;
      setIncidents(data.items);
      setIncidentPage(data.page);
    } catch (err) {
      if (!isCurrent()) return;
      if (!options.silent) {
        setIncidents([]);
        setIncidentPage(emptyPage(pageIndexes.incidents));
      }
      setIncidentsError(err instanceof Error ? err.message : 'Failed to load incidents.');
    } finally {
      if (isCurrent()) {
        setIncidentsLoading(false);
      }
    }
  }, [incidentFilters, incidentView, pageIndexes.incidents]);

  const loadAlerts = useCallback(async (options: { silent?: boolean } = {}) => {
    const version = ++alertsVersionRef.current;
    const isCurrent = () => version === alertsVersionRef.current;
    if (!options.silent) {
      setAlertsLoading(true);
    }
    setAlertsError('');
    try {
      const data = await fetchAlerts(pageRequest(pageIndexes.alerts), alertFilters);
      if (!isCurrent()) return;
      setAlerts(data.items);
      setAlertPage(data.page);
    } catch (err) {
      if (!isCurrent()) return;
      if (!options.silent) {
        setAlerts([]);
        setAlertPage(emptyPage(pageIndexes.alerts));
      }
      setAlertsError(err instanceof Error ? err.message : 'Failed to load alerts.');
    } finally {
      if (isCurrent()) {
        setAlertsLoading(false);
      }
    }
  }, [alertFilters, pageIndexes.alerts]);

  const loadAnalysis = useCallback(async (options: { silent?: boolean } = {}) => {
    const version = ++analysisVersionRef.current;
    const isCurrent = () => version === analysisVersionRef.current;
    if (!options.silent) {
      setAnalysisLoading(true);
    }
    setAnalysisError('');
    try {
      const data = await fetchAnalysisRuns(pageRequest(pageIndexes.analysis));
      if (!isCurrent()) return false;
      setAnalysisRuns(data.items);
      setAnalysisPage(data.page);
      return true;
    } catch (err) {
      if (!isCurrent()) return false;
      if (!options.silent) {
        setAnalysisRuns([]);
        setAnalysisPage(emptyPage(pageIndexes.analysis));
      }
      const message = err instanceof Error ? err.message : 'Failed to load analysis runs.';
      setAnalysisError(`Analysis runs are unavailable: ${message}`);
      return false;
    } finally {
      if (isCurrent()) {
        setAnalysisLoading(false);
      }
    }
  }, [pageIndexes.analysis]);

  // Full refresh (mount, SSE debounce, explicit reloads). Resolves to whether
  // the analysis list loaded: the SSE handler gates clearing completed
  // progress runs on that.
  const load = useCallback(async (options: { silent?: boolean } = {}) => {
    const [, , analysisLoaded] = await Promise.all([
      loadIncidents(options),
      loadAlerts(options),
      loadAnalysis(options),
    ]);
    return analysisLoaded;
  }, [loadAlerts, loadAnalysis, loadIncidents]);

  useEffect(() => {
    void loadIncidents();
  }, [loadIncidents]);

  useEffect(() => {
    void loadAlerts();
  }, [loadAlerts]);

  useEffect(() => {
    void loadAnalysis();
  }, [loadAnalysis]);

  // The SSE subscription lives for the whole session; handlers reach the
  // latest load through a ref so page flips and filter changes never tear the
  // EventSource down and reconnect it.
  const loadRef = useRef(load);
  loadRef.current = load;

  useEffect(() => {
    let source: EventSource;
    try {
      source = eventSource();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Realtime updates are unavailable.';
      setRealtimeError(`Realtime updates are unavailable: ${message}`);
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
        const analysisLoaded = await loadRef.current({ silent: true });
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
  }, []);

  const loading = incidentsLoading || alertsLoading || analysisLoading;
  const error = useMemo(
    () => [incidentsError, alertsError, analysisError, realtimeError].filter(Boolean).join('; '),
    [alertsError, analysisError, incidentsError, realtimeError],
  );

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
