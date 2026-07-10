import {
  Activity,
  AlertTriangle,
  Archive,
  ArrowLeft,
  Bot,
  CheckCircle2,
  ChevronDown,
  Database,
  Download,
  FileText,
  LineChart,
  Link,
  ListChecks,
  MessageSquare,
  RefreshCw,
  Search,
  Server,
  Cpu,
  ThumbsDown,
  ThumbsUp,
  Trash2,
  X,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {
  analyzeIncident,
  archiveIncident,
  deleteIncident,
  fetchIncident,
  resolveIncident,
  restoreIncident,
  unarchiveIncident,
} from '../api';
import nvidiaLogo from '../assets/nvidia-logo.svg';
import { CopyableBlock } from './common/UiParts';
import { AnalysisDashboard } from './dashboards/AnalysisDashboard';
import { AlertsDashboard } from './dashboards/AlertsDashboard';
import { ChatDashboard } from './dashboards/ChatDashboard';
import { IncidentsDashboard } from './dashboards/IncidentsDashboard';
import { FeedbackPanel } from './workspace/FeedbackPanel';
import { EvaluationPanel } from './workspace/EvaluationPanel';
import { FloatingChat } from './workspace/FloatingChat';
import { useRcaChat } from './workspace/chatSession';
import { exportIncidentDocx } from '../exportDocx';
import { useDashboardData } from '../hooks/useDashboardData';
import { useEditorHistory } from '../hooks/useEditorHistory';
import {
  AGENT_ORDER,
  ANALYSIS_AGENT_ID,
  COMPONENT_AGENT_ORDER,
  DEFAULT_ALERT_FILTERS,
  DEFAULT_INCIDENT_FILTERS,
  VIEW_COPY,
  type AgentSummary,
  type AlertFilterState,
  type AnalysisRecord,
  type DetailState,
  type EvidenceItem,
  type IncidentFilterState,
  type MainView,
  type QueryDisplayItem,
  type RouteState,
  type SynthesisSummary,
} from '../models/appTypes';
import { AlertRecord, AnalysisProgressEntry, AnalysisRun, Artifact, Incident, SimilarIncident } from '../types';
import { buildAnalysisRecords } from '../utils/analytics';
import { alertFiltersForAPI, incidentFiltersForAPI, incidentViewForMainView, matchesAlertFilters, matchesIncidentFilters } from '../utils/filters';
import {
  FinalDecision,
  Severity,
  Status,
  agentIcon,
  agentLabel,
  formatOccurrenceCount,
  formatTime,
  formatTokenUsage,
  isCollectorAgent,
  latestAgentSignal,
  latestEvidenceForAgent,
  targetLine,
  uniqueStrings,
} from '../utils/formatters';
import { RealtimeEventPayload } from '../utils/realtime';
import { hashForDetail, hashForView, routeFromHash } from '../utils/routing';

function errorMessage(err: unknown, fallback: string) {
  return err instanceof Error ? err.message : fallback;
}

function formatArtifactValue(value: unknown) {
  return typeof value === 'string' ? value : safeJSONStringify(value, 2);
}

function safeJSONStringify(value: unknown, space?: number) {
  const seen = new WeakSet<object>();
  try {
    const serialized = JSON.stringify(
      value,
      (_key, item) => {
        if (typeof item !== 'object' || item === null) {
          return item;
        }
        if (seen.has(item)) {
          return '[Circular]';
        }
        seen.add(item);
        return item;
      },
      space,
    );
    return serialized ?? String(value);
  } catch (err) {
    return `[Unserializable: ${errorMessage(err, 'unknown value')}]`;
  }
}

function compactArtifactValue(value: unknown, depth = 3): unknown {
  if (depth <= 0) {
    if (Array.isArray(value)) return `[${value.length} item(s)]`;
    if (isPlainObject(value)) return '{...}';
    return value;
  }
  if (Array.isArray(value)) {
    const trimmed = value.slice(0, 4).map((item) => compactArtifactValue(item, depth - 1));
    if (value.length > 4) {
      trimmed.push({ truncated: value.length - 4 });
    }
    return trimmed;
  }
  if (!isPlainObject(value)) return value;

  const priorityKeys = [
    'name',
    'namespace',
    'path',
    'query',
    'status',
    'status_code',
    'error',
    'reason',
    'message',
    'phase',
    'nodeName',
    'ready',
    'restartCount',
    'line_count',
    'stream_count',
    'items',
    'conditions',
    'containerStatuses',
    'data',
    'sample',
  ];
  const keys = Object.keys(value);
  const selected = [
    ...priorityKeys.filter((key) => key in value),
    ...keys.filter((key) => !priorityKeys.includes(key)),
  ].slice(0, 9);

  const compacted: Record<string, unknown> = {};
  for (const key of selected) {
    compacted[key] = compactArtifactValue(value[key], depth - 1);
  }
  if (keys.length > selected.length) {
    compacted.truncated_keys = keys.length - selected.length;
  }
  return compacted;
}

function queryDisplayItems(result: unknown): QueryDisplayItem[] {
  if (!isPlainObject(result) || !Array.isArray(result.queries)) return [];
  return result.queries
    .filter(isPlainObject)
    .map((query, index) => {
      const name = stringValue(query.name) || `query_${index + 1}`;
      const statusCode = numberValue(query.status_code);
      const error = stringValue(query.error);
      const rawStatus = stringValue(query.status);
      // Collectors that pre-extract the salient content (e.g. Loki's flat
      // sample_lines: the actual log text) win over the nested sample/data,
      // which compactArtifactValue would otherwise crush to "[N item(s)]".
      const sampleLines = Array.isArray(query.sample_lines) ? (query.sample_lines as unknown[]) : undefined;
      const previewSource = query.sample !== undefined ? query.sample : query.data;
      // A query failed if the transport 4xx/5xx'd OR the response BODY reports an
      // error. MCP builders stamp a fixed status_code:200/error:None and hide the
      // real failure in the body — runai as a numeric {status:404,…}, Prometheus/
      // Loki as a "error" status. Any of these must render red, not a green pill.
      const bodyStatus = isPlainObject(previewSource) ? numberValue(previewSource.status) : undefined;
      const failed =
        Boolean(error) ||
        (statusCode !== undefined && statusCode >= 400) ||
        (bodyStatus !== undefined && bodyStatus >= 400) ||
        rawStatus === 'error';
      const status = failed ? 'failed' : rawStatus || (statusCode ? String(statusCode) : 'ok');
      const queryText = stringValue(query.query) || stringValue(query.path) || stringValue(query.url) || '';
      const facts = [
        statusCode ? `HTTP ${statusCode}` : '',
        numberValue(query.stream_count) !== undefined ? `${numberValue(query.stream_count)} stream(s)` : '',
        numberValue(query.line_count) !== undefined ? `${numberValue(query.line_count)} line(s)` : '',
        error ? error : '',
      ].filter(Boolean);
      return {
        id: `${name}-${index}`,
        name: humanizeKey(name),
        queryText,
        queryLabel: query.query ? 'Query' : query.path ? 'Path' : 'URL',
        status,
        statusCode,
        error,
        facts,
        preview: sampleLines ?? (previewSource === undefined ? undefined : compactArtifactValue(previewSource)),
      };
    });
}

function stringValue(value: unknown) {
  return typeof value === 'string' ? value : '';
}

function numberValue(value: unknown) {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

// Empty results ([], {}, "") are noise — collectors that ran and found nothing
// still show their status/facts, just not a barren "Relevant result: []".
function isEmptyResult(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  if (Array.isArray(value)) return value.length === 0;
  if (isPlainObject(value)) return Object.keys(value).length === 0;
  if (typeof value === 'string') return value.trim() === '';
  return false;
}

function humanizeKey(value: string) {
  return value.replace(/[_:]/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function realtimeEventMatchesDetail(detail: DetailState, payload: RealtimeEventPayload | undefined) {
  if (!detail || !payload?.data) return false;
  const data = payload.data;
  if (detail.kind === 'incident') {
    const incidentID = detail.data.incident_id;
    return (
      data.incident_id === incidentID ||
      (data.target_type === 'incident' && data.target_id === incidentID) ||
      detail.data.alerts.some((alert) => data.alert_id === alert.alert_id || (data.target_type === 'alert' && data.target_id === alert.alert_id))
    );
  }
  const alertID = detail.data.alert_id;
  return (
    data.alert_id === alertID ||
    (data.target_type === 'alert' && data.target_id === alertID) ||
    (data.target_type === 'incident' && data.target_id === detail.data.incident_id)
  );
}

function analysisRunMatchesDetail(run: AnalysisRun, detail: DetailState) {
  if (!detail) return false;
  if (detail.kind === 'incident') {
    const incidentID = detail.data.incident_id;
    const alertIDs = new Set(detail.data.alerts.map((alert) => alert.alert_id));
    return (
      run.incident_id === incidentID ||
      (run.target_type === 'incident' && run.target_id === incidentID) ||
      (run.alert_id ? alertIDs.has(run.alert_id) : false) ||
      (run.target_type === 'alert' && alertIDs.has(run.target_id))
    );
  }
  const alertID = detail.data.alert_id;
  return (
    run.alert_id === alertID ||
    (run.target_type === 'alert' && run.target_id === alertID) ||
    run.incident_id === detail.data.incident_id ||
    (run.target_type === 'incident' && run.target_id === detail.data.incident_id)
  );
}

function latestAnalysisRunForDetail(detail: DetailState, runs: AnalysisRun[]) {
  return [...runs]
    .filter((run) => analysisRunMatchesDetail(run, detail))
    .sort((left, right) => right.updated_at.localeCompare(left.updated_at))[0];
}

function progressForRun(
  run: AnalysisRun | undefined,
  progressByRun: Record<string, AnalysisProgressEntry[]>,
) {
  if (!run) return [];
  const live = progressByRun[run.run_id] ?? [];
  if (live.length > 0) return live;
  return Array.isArray(run.metadata?.progress_log) ? run.metadata.progress_log : [];
}

function App() {
  const [activeView, setActiveView] = useState<MainView>(() => routeFromHash(window.location.hash).view);
  const [incidentPageIndex, setIncidentPageIndex] = useState(0);
  const [alertPageIndex, setAlertPageIndex] = useState(0);
  const [analysisPageIndex, setAnalysisPageIndex] = useState(0);
  const [incidentFilters, setIncidentFilters] = useState<IncidentFilterState>(DEFAULT_INCIDENT_FILTERS);
  const [alertFilters, setAlertFilters] = useState<AlertFilterState>(DEFAULT_ALERT_FILTERS);
  const [query, setQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  useEffect(() => {
    const handle = window.setTimeout(() => setDebouncedQuery(query.trim()), 300);
    return () => window.clearTimeout(handle);
  }, [query]);
  const incidentQueryFilters = useMemo(
    () => ({ ...incidentFiltersForAPI(incidentFilters), search: debouncedQuery || undefined }),
    [incidentFilters, debouncedQuery],
  );
  const alertQueryFilters = useMemo(
    () => ({ ...alertFiltersForAPI(alertFilters), search: debouncedQuery || undefined }),
    [alertFilters, debouncedQuery],
  );
  const {
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
  } = useDashboardData({
    incidents: incidentPageIndex,
    alerts: alertPageIndex,
    analysis: analysisPageIndex,
  }, incidentViewForMainView(activeView), incidentQueryFilters, alertQueryFilters);
  const [detail, setDetail] = useState<DetailState>(null);
  const [chatDocked, setChatDocked] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const detailVersionRef = useRef(0);
  const routeLoadVersionRef = useRef(0);

  useEffect(() => {
    setIncidentPageIndex(0);
    setAlertPageIndex(0);
    setAnalysisPageIndex(0);
  }, [debouncedQuery]);

  useEffect(() => {
    setIncidentPageIndex(0);
  }, [activeView, incidentFilters]);

  useEffect(() => {
    setAlertPageIndex(0);
  }, [alertFilters]);

  useEffect(() => {
    detailVersionRef.current += 1;
  }, [detail]);

  const dashboardIncidents = incidents;
  const dashboardAlerts = alerts;
  const analysisIncidents = incidents;
  const analysisAlerts = alerts;
  const dashboardAnalysisRuns = analysisRuns;

  // Text search is executed server-side (title + RCA content + labels/annotations,
  // across the whole dataset — not just this page). Only the status/severity
  // structural filters remain client-side.
  const filteredIncidents = useMemo(
    () => dashboardIncidents.filter((incident) => matchesIncidentFilters(incident, incidentFilters)),
    [dashboardIncidents, incidentFilters],
  );

  const filteredAlerts = useMemo(
    () => dashboardAlerts.filter((alert) => matchesAlertFilters(alert, alertFilters)),
    [alertFilters, dashboardAlerts],
  );

  const analysisRecords = useMemo(
    () => buildAnalysisRecords(dashboardAnalysisRuns),
    [dashboardAnalysisRuns],
  );

  const liveEvidenceItems = useMemo<EvidenceItem[]>(() => {
    // Evidence artifacts live on the analysis runs now (not per-alert columns).
    return dashboardAnalysisRuns.flatMap((run) =>
      (run.artifacts ?? [])
        .filter((artifact) => isCollectorAgent(artifact.agent))
        .map((artifact, index) => ({
          id: `${run.run_id}-${artifact.agent}-${artifact.type}-${index}`,
          title: artifact.summary || `${agentLabel(artifact.agent)} ${artifact.type}`,
          agent: artifact.agent,
          source: artifact.source,
          type: artifact.type,
          status: artifact.status || 'ok',
          confidence: artifact.confidence || 'medium',
          target: `${run.target_type} / ${run.target_id}`,
          summary: artifact.summary || 'Evidence was collected without a summary.',
          query: artifact.query,
          result: artifact.result,
          alertID: run.alert_id,
          incidentID: run.incident_id,
          createdAt: run.created_at,
        })),
    );
  }, [dashboardAnalysisRuns]);

  const agentSummaries = useMemo<AgentSummary[]>(() => {
    return COMPONENT_AGENT_ORDER.map((agent) => {
      const agentEvidence = latestEvidenceForAgent(liveEvidenceItems, agent);
      const signal = latestAgentSignal(analysisRecords, agentEvidence, agent);
      return {
        id: `agent-${agent}`,
        agent,
        name: agentLabel(agent),
        status: signal.status,
        summary:
          agentEvidence.length > 0
            ? `${agentEvidence.length} collector evidence item(s) linked to recent RCA context.`
            : 'No collector evidence has been collected by this agent yet.',
        source: signal.source,
        lastRun: signal.lastRun,
        evidenceCount: agentEvidence.length,
      };
    });
  }, [analysisRecords, liveEvidenceItems]);

  const synthesisSummary = useMemo<SynthesisSummary>(() => {
    const latest = analysisRecords[0];
    return {
      id: 'synthesis-analysis',
      name: 'RCA Synthesis',
      status: analysisRecords.some((record) => record.isAnalyzing)
        ? 'analyzing'
        : analysisRecords.some((record) => record.detail || record.summary)
          ? 'ok'
          : 'pending',
      summary:
        analysisRecords.length > 0
          ? `${analysisRecords.length} RCA synthesis run(s) tracked across current incidents and alerts.`
          : 'No RCA synthesis runs have been created yet.',
      source: 'nemo.analysis_agent',
      lastRun: latest?.createdAt || '-',
      runCount: analysisRecords.length,
    };
  }, [analysisRecords]);

  const workspaceAnalysisRun = useMemo(
    () => latestAnalysisRunForDetail(detail, dashboardAnalysisRuns),
    [dashboardAnalysisRuns, detail],
  );
  const workspaceProgress = useMemo(
    () => progressForRun(workspaceAnalysisRun, progressByRun),
    [progressByRun, workspaceAnalysisRun],
  );

  const loadRoute = useCallback(async (route: RouteState) => {
    const version = routeLoadVersionRef.current + 1;
    routeLoadVersionRef.current = version;
    setActiveView(route.view);
    if (!route.detailKind || !route.detailID) {
      setDetail(null);
      return;
    }
    try {
      if (route.detailKind === 'incident') {
        const nextDetail = await fetchIncident(route.detailID);
        if (routeLoadVersionRef.current === version) {
          setDetail({ kind: 'incident', data: nextDetail });
        }
        return;
      }
      // Alerts are list-only — there is no per-alert detail view. A stale
      // alert-detail route just falls back to the list.
      if (routeLoadVersionRef.current === version) {
        setDetail(null);
      }
    } catch {
      if (routeLoadVersionRef.current === version) {
        setDetail(null);
      }
    }
  }, []);

  useEffect(() => {
    if (!window.location.hash) {
      window.history.replaceState(null, '', hashForView('incidents'));
    }
    const handleHashChange = () => {
      void loadRoute(routeFromHash(window.location.hash));
    };
    handleHashChange();
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, [loadRoute]);

  const navigateToHash = useCallback((hash: string) => {
    if (window.location.hash === hash) {
      void loadRoute(routeFromHash(hash));
      return;
    }
    window.location.hash = hash;
  }, [loadRoute]);

  const viewCopy = VIEW_COPY[activeView];

  const goHome = () => navigateToHash(hashForView('incidents'));

  const switchView = (view: MainView) => {
    navigateToHash(hashForView(view));
  };

  const closeDetail = () => navigateToHash(hashForView(activeView));

  const openIncident = useCallback(async (id: string) => {
    const view = activeView === 'archived' || activeView === 'trash' ? activeView : 'incidents';
    navigateToHash(hashForDetail('incident', id, view));
  }, [activeView, navigateToHash]);

  const refreshDetail = useCallback(async () => {
    const currentDetail = detail;
    const version = detailVersionRef.current;
    if (!currentDetail || currentDetail.kind !== 'incident') return;
    const nextDetail = await fetchIncident(currentDetail.data.incident_id);
    if (detailVersionRef.current === version) {
      setDetail({ kind: 'incident', data: nextDetail });
    }
  }, [detail]);

  const refreshCurrentView = useCallback(async () => {
    if (refreshing) return;
    setRefreshing(true);
    try {
      await Promise.all([load({ silent: true }), refreshDetail()]);
    } finally {
      setRefreshing(false);
    }
  }, [load, refreshDetail, refreshing]);

  const handleArchiveIncident = useCallback(async (id: string) => {
    await archiveIncident(id);
    await refreshCurrentView();
  }, [refreshCurrentView]);

  const handleUnarchiveIncident = useCallback(async (id: string) => {
    await unarchiveIncident(id);
    await refreshCurrentView();
  }, [refreshCurrentView]);

  const handleRestoreIncident = useCallback(async (id: string) => {
    await restoreIncident(id);
    await refreshCurrentView();
  }, [refreshCurrentView]);

  const handleDeleteIncident = useCallback(async (id: string, permanent = false) => {
    await deleteIncident(id, permanent);
    await refreshCurrentView();
  }, [refreshCurrentView]);

  const chatSession = useRcaChat({
    detail,
    activeView,
    incidents: dashboardIncidents,
    alerts: dashboardAlerts,
    onAnalysisCreated: () => load({ silent: true }),
  });

  // Refresh the open detail ONLY when a genuinely new realtime event arrives.
  // refreshDetail() calls setDetail(), which changes `detail`, which recreates
  // refreshDetail (its dep) — so keying this effect on those would re-fire it on
  // its own output while `realtimePayload` kept matching, hammering the detail
  // endpoint ~1×/sec forever. Gate on the payload identity to break that loop.
  const lastRealtimePayloadRef = useRef<RealtimeEventPayload | undefined>(undefined);
  useEffect(() => {
    if (!realtimePayload || realtimePayload === lastRealtimePayloadRef.current) return;
    lastRealtimePayloadRef.current = realtimePayload;
    if (realtimeEventMatchesDetail(detail, realtimePayload)) {
      void refreshDetail();
    }
  }, [detail, realtimePayload, refreshDetail]);

  return (
    <div className={`app-shell ${chatDocked ? 'chat-docked' : ''}`}>
      <aside className="sidebar">
        <button className="brand-mark" onClick={goHome} type="button" aria-label="Go to incidents dashboard">
          <img className="brand-logo" src={nvidiaLogo} alt="NVIDIA" />
        </button>
        <div>
          <p className="eyebrow">NVIDIA Run:ai</p>
          <h1>Run:AI RCA</h1>
        </div>
        <nav className="primary-nav">
          <button
            className={`nav-item ${activeView === 'incidents' ? 'active' : ''}`}
            onClick={() => switchView('incidents')}
            type="button"
          >
            <Activity size={18} /> Incident
          </button>
          <button
            className={`nav-item ${activeView === 'alerts' ? 'active' : ''}`}
            onClick={() => switchView('alerts')}
            type="button"
          >
            <AlertTriangle size={18} /> Alerts
          </button>
          <button
            className={`nav-item ${activeView === 'analysis' ? 'active' : ''}`}
            onClick={() => switchView('analysis')}
            type="button"
          >
            <ListChecks size={18} /> Analysis
          </button>
          <button
            className={`nav-item ${activeView === 'chat' ? 'active' : ''}`}
            onClick={() => switchView('chat')}
            type="button"
          >
            <MessageSquare size={18} /> Chat
          </button>
        </nav>
        <nav className="utility-nav" aria-label="Incident lifecycle views">
          <button
            className={`nav-item icon-only-nav-item ${activeView === 'archived' ? 'active' : ''}`}
            onClick={() => switchView('archived')}
            type="button"
            aria-label="Archive"
            title="Archive"
          >
            <Archive size={18} />
            <span className="sr-only">Archive</span>
          </button>
          <button
            className={`nav-item icon-only-nav-item ${activeView === 'trash' ? 'active' : ''}`}
            onClick={() => switchView('trash')}
            type="button"
            aria-label="Trash"
            title="Trash"
          >
            <Trash2 size={18} />
            <span className="sr-only">Trash</span>
          </button>
        </nav>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <p className="eyebrow">{viewCopy.eyebrow}</p>
            <h2>{viewCopy.title}</h2>
          </div>
          <div className="search-box">
            <Search size={17} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={viewCopy.placeholder}
            />
          </div>
          <button
            className={`icon-button ${refreshing ? 'is-spinning' : ''}`}
            disabled={refreshing}
            onClick={() => void refreshCurrentView()}
            aria-label="Refresh"
          >
            <RefreshCw size={18} />
          </button>
        </header>

        {(loading || refreshing) && (
          <div className="loading-strip" role="status" aria-live="polite">
            <span />
            <strong>{refreshing ? 'Refreshing data...' : 'Loading dashboard...'}</strong>
          </div>
        )}

        {error && <div className="error-banner">{error}</div>}

        {(activeView === 'incidents' || activeView === 'archived' || activeView === 'trash') && (
          <IncidentsDashboard
            view={incidentViewForMainView(activeView)}
            incidents={dashboardIncidents}
            filteredIncidents={filteredIncidents}
            filters={incidentFilters}
            page={incidentPage}
            loading={loading}
            onOpenIncident={openIncident}
            onPageChange={setIncidentPageIndex}
            onFilterChange={setIncidentFilters}
            onArchive={handleArchiveIncident}
            onUnarchive={handleUnarchiveIncident}
            onRestore={handleRestoreIncident}
            onDelete={handleDeleteIncident}
          />
        )}
        {activeView === 'alerts' && (
          <AlertsDashboard
            alerts={dashboardAlerts}
            filteredAlerts={filteredAlerts}
            filters={alertFilters}
            page={alertPage}
            loading={loading}
            onOpenIncident={openIncident}
            onPageChange={setAlertPageIndex}
            onFilterChange={setAlertFilters}
          />
        )}
        {activeView === 'analysis' && (
          <AnalysisDashboard
            allRecords={analysisRecords}
            agents={agentSummaries}
            synthesis={synthesisSummary}
            incidents={analysisIncidents}
            alerts={analysisAlerts}
          />
        )}
        {activeView === 'chat' && (
          <ChatDashboard chat={chatSession} query={query} />
        )}
      </main>

      <UnifiedWorkspace
        detail={detail}
        analysisRun={workspaceAnalysisRun}
        progressEvents={workspaceProgress}
        onClose={closeDetail}
        onRefresh={refreshDetail}
        onAnalyze={async (id) => {
          await analyzeIncident(id);
          await refreshCurrentView();
        }}
        onOpenIncident={openIncident}
        onResolve={async (id) => {
          await resolveIncident(id);
          await refreshCurrentView();
        }}
      />
      <FloatingChat
        chat={chatSession}
        onDockedChange={setChatDocked}
      />
    </div>
  );
}

function UnifiedWorkspace({
  detail,
  analysisRun,
  progressEvents,
  onClose,
  onRefresh,
  onAnalyze,
  onOpenIncident,
  onResolve,
}: {
  detail: DetailState;
  analysisRun?: AnalysisRun;
  progressEvents: AnalysisProgressEntry[];
  onClose: () => void;
  onRefresh: () => Promise<void>;
  onAnalyze: (id: string) => Promise<void>;
  onOpenIncident: (id: string) => Promise<void>;
  onResolve: (id: string) => Promise<void>;
}) {
  const [busyAction, setBusyAction] = useState('');
  const runWorkspaceAction = useCallback(async (action: string, work: () => Promise<void>) => {
    if (busyAction) return;
    setBusyAction(action);
    try {
      await work();
    } finally {
      setBusyAction('');
    }
  }, [busyAction]);

  if (!detail) return null;
  const incident = detail.kind === 'incident' ? detail.data : null;
  const alert = detail.kind === 'alert' ? detail.data : null;
  const title = incident?.title ?? alert?.alarm_title ?? '';
  const id = incident?.incident_id ?? alert?.alert_id ?? '';
  const labels = incident?.alerts[0]?.labels ?? alert?.labels ?? {};
  const affectedPods = incident
    ? Array.from(new Set(incident.alerts.flatMap((item) => item.occurrence_pods ?? []))).filter(Boolean)
    : (alert?.occurrence_pods ?? []).filter(Boolean);
  const artifacts = incident?.artifacts ?? [];
  const capabilities = incident?.capabilities ?? {};
  const missingData = incident?.missing_data ?? [];
  const warnings = incident?.warnings ?? [];
  const tokenUsage = incident?.token_usage;
  const analysis = incident?.analysis_detail;
  const summary = incident?.analysis_summary;
  const isAnalyzing = Boolean(detail.data.is_analyzing);
  const similarIncidents = incident?.similar_incidents ?? [];
  const feedback = incident?.feedback ?? alert?.feedback;
  const targetType = detail.kind;
  const positiveFeedback = feedback?.positive ?? 0;
  const negativeFeedback = feedback?.negative ?? 0;
  const commentCount = feedback?.comments?.length ?? 0;
  const scrollToFeedback = () => {
    document.getElementById('operator-feedback')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <section className="workspace">
      <div className="workspace-header">
        <div>
          <p className="eyebrow">{detail.kind} detail</p>
          <h2>{title}</h2>
          <div className="meta-line">
            <span className="entity-id">{id}</span>
            <span>{targetLine(labels)}</span>
          </div>
          <div className="meta-line">
            <span>Severity</span>
            <Severity value={detail.data.severity} />
            <span>Incident status</span>
            <Status value={detail.data.status} analyzing={detail.data.is_analyzing} />
            {incident && (
              <>
                <span>Final decision</span>
                <FinalDecision approvedAt={incident.user_approved_at} />
              </>
            )}
          </div>
          <div className="meta-line meta-time">
            <span>Fired: {formatTime(detail.data.fired_at)}</span>
            <span>Alertmanager resolved: {detail.data.resolved_at ? formatTime(detail.data.resolved_at) : '—'}</span>
            {incident && <span>User approved: {incident.user_approved_at ? formatTime(incident.user_approved_at) : '—'}</span>}
          </div>
          <AffectedPods pods={affectedPods} />
        </div>
        <div className="workspace-actions">
          <button className="ghost-button" onClick={onClose} type="button"><ArrowLeft size={16} /> Back</button>
          <button
            className={`ghost-button ${busyAction === 'refresh' ? 'is-busy is-spinning' : ''}`}
            disabled={Boolean(busyAction)}
            onClick={() => void runWorkspaceAction('refresh', onRefresh)}
            type="button"
          >
            <RefreshCw size={16} /> {busyAction === 'refresh' ? 'Refreshing...' : 'Refresh'}
          </button>
          {incident && (
            <>
              <button
                className={`ghost-button ${busyAction === 'analyze' ? 'is-busy' : ''}`}
                disabled={Boolean(busyAction)}
                onClick={() => void runWorkspaceAction('analyze', () => onAnalyze(incident.incident_id))}
                type="button"
              >
                <Bot size={16} /> {busyAction === 'analyze' ? 'Analyzing...' : 'Analyze'}
              </button>
              <button
                className={`ghost-button ${busyAction === 'export' ? 'is-busy' : ''}`}
                disabled={Boolean(busyAction)}
                onClick={() => void runWorkspaceAction('export', () => exportIncidentDocx(incident))}
                type="button"
              >
                <Download size={16} /> {busyAction === 'export' ? 'Exporting...' : 'Export'}
              </button>
              <button
                className={`primary-button ${busyAction === 'resolve' ? 'is-busy' : ''}`}
                disabled={Boolean(busyAction)}
                onClick={() => void runWorkspaceAction('resolve', () => onResolve(incident.incident_id))}
                type="button"
              >
                <CheckCircle2 size={16} /> {busyAction === 'resolve' ? 'Updating...' : incident.user_approved_at ? 'Unapprove' : 'Approve'}
              </button>
            </>
          )}
          {alert && (
            <>
              <button
                className={`ghost-button ${busyAction === 'open-incident' ? 'is-busy' : ''}`}
                disabled={Boolean(busyAction)}
                onClick={() => void runWorkspaceAction('open-incident', () => onOpenIncident(alert.incident_id))}
                type="button"
              >
                <Link size={16} /> Incident
              </button>
              <button
                className={`ghost-button ${busyAction === 'analyze' ? 'is-busy' : ''}`}
                disabled={Boolean(busyAction)}
                onClick={() => void runWorkspaceAction('analyze', () => onAnalyze(alert.incident_id))}
                type="button"
              >
                <Bot size={16} /> {busyAction === 'analyze' ? 'Analyzing...' : 'Analyze'}
              </button>
            </>
          )}
        </div>
      </div>

      {busyAction && (
        <div className="workspace-progress" role="status" aria-live="polite">
          <span />
        </div>
      )}

      <div className="workspace-body">
        <section className="rca-summary">
          <h3>RCA Summary</h3>
          <p>
            {summary ||
              (isAnalyzing
                ? 'Analysis is running. New RCA content will appear when the agent finishes.'
                : 'Analysis is pending. The Collector Evidence Trail will populate as collectors finish.')}
          </p>
          <div className="rca-feedback-strip">
            <span><ThumbsUp size={15} /> {positiveFeedback}</span>
            <span><ThumbsDown size={15} /> {negativeFeedback}</span>
            <span><MessageSquare size={15} /> {commentCount}</span>
            <button className="ghost-button compact-button" onClick={scrollToFeedback} type="button">
              <MessageSquare size={14} /> Feedback
            </button>
          </div>
        </section>

        {(isAnalyzing || progressEvents.length > 0) && (
          <ProgressTimeline
            events={progressEvents}
            live={isAnalyzing || analysisRun?.status === 'analyzing'}
            run={analysisRun}
          />
        )}

        {incident && (
          <SimilarIncidentsPanel items={similarIncidents} recentCount={incident.similar_recent_count ?? 0} />
        )}

        <section className="rca-report">
          <div className="section-title"><FileText size={18} /> Report</div>
          {isAnalyzing ? (
            // While a run is in flight the previous report is stale — showing it
            // confused operators into reading the old RCA as the new result.
            <p className="empty">Analyzing… a new RCA report is being generated. The previous report will be replaced when it completes.</p>
          ) : analysis ? (
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{analysis}</ReactMarkdown>
          ) : (
            <p className="empty">No RCA report yet.</p>
          )}
        </section>

        <section className="agent-trail">
          <div className="section-title"><Bot size={18} /> Collector Evidence Trail</div>
          <div className="agent-grid">
            {AGENT_ORDER.map((agent) => (
              <AgentEvidence
                key={agent}
                agent={agent}
                status={capabilities[agent] || 'pending'}
                artifacts={artifacts.filter((artifact) => artifact.agent === agent)}
                reasons={agentReasons(agent, missingData, warnings)}
              />
            ))}
          </div>
        </section>

        {(missingData.length > 0 || warnings.length > 0 || tokenUsage) && (
          <DiagnosticsPanel missingData={missingData} warnings={warnings} tokenUsage={tokenUsage} />
        )}

        <EvaluationPanel
          runID={incident?.analysis_run_id}
          analysisHash={incident?.analysis_hash}
          harness={incident?.harness}
          onSaved={onRefresh}
        />

        <FeedbackPanel
          targetType={targetType}
          targetID={id}
          feedback={feedback}
          onSubmitted={onRefresh}
        />
      </div>
    </section>
  );
}

function ProgressTimeline({
  events,
  live,
  run,
}: {
  events: AnalysisProgressEntry[];
  live: boolean;
  run?: AnalysisRun;
}) {
  const [open, setOpen] = useState(live);
  useEffect(() => {
    if (live) setOpen(true);
  }, [live]);
  const visible = events.slice(-12);
  const ledger = latestProgressLedger(events);
  return (
    <section className={`progress-timeline ${live ? 'is-live' : ''}`}>
      <button className="progress-timeline-head" onClick={() => setOpen((value) => !value)} type="button">
        <span><ListChecks size={18} /> Thought Process</span>
        <span className="progress-timeline-meta">
          {live ? 'live' : run?.updated_at ? formatTime(run.updated_at) : 'complete'}
          <ChevronDown size={15} />
        </span>
      </button>
      {open && (
        <div className="progress-timeline-body">
          {ledger.length > 0 && (
            <div className="hypothesis-strip">
              {ledger.slice(0, 4).map((item) => {
                // 0.5 with status "open" is the investigator's untouched seed, not a
                // computed probability — showing "50%" on every chip misled operators.
                const seeded = String(item.status || 'open') === 'open' && item.confidence === 0.5;
                return (
                  <span key={String(item.id)} className={`hypothesis-chip status-${String(item.status || 'open')}`}>
                    <strong>{String(item.family || item.id || 'hypothesis').replace(/_/g, ' ')}</strong>
                    {typeof item.confidence === 'number' && !seeded && <em>{Math.round(item.confidence * 100)}%</em>}
                  </span>
                );
              })}
            </div>
          )}
          {visible.length === 0 ? (
            <p className="empty">Analysis has started. Waiting for the first reasoning update.</p>
          ) : (
            <ol className="progress-events">
              {visible.map((event, index) => (
                <li key={`${event.seq ?? index}-${event.phase ?? 'phase'}`}>
                  <span className="progress-dot" />
                  <div>
                    <div className="progress-event-head">
                      <strong>{progressEventTitle(event)}</strong>
                      <time>{formatProgressTimestamp(event.timestamp)}</time>
                    </div>
                    {event.message && <p>{String(event.message)}</p>}
                  </div>
                </li>
              ))}
            </ol>
          )}
        </div>
      )}
    </section>
  );
}

function latestProgressLedger(events: AnalysisProgressEntry[]) {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const ledger = events[index].hypothesis_ledger;
    if (Array.isArray(ledger)) return ledger as Array<Record<string, unknown>>;
  }
  return [];
}

const PHASE_LABELS: Record<string, string> = {
  enrich: 'Enrichment',
  plan: 'Planning',
  planning: 'Planning',
  evidence: 'Evidence',
  collection: 'Evidence',
  rank: 'Ranking',
  ranking: 'Ranking',
  self_check: 'Self-check',
  synthesize: 'Synthesis',
  reflection: 'Synthesis',
};

function progressEventTitle(event: AnalysisProgressEntry) {
  const rawPhase = String(event.phase || 'progress');
  const phase = PHASE_LABELS[rawPhase] || rawPhase.replace(/_/g, ' ');
  if (event.collector) return `${phase} · ${agentLabel(String(event.collector))}`;
  if (event.selected_hypothesis) return `${phase} · ${String(event.selected_hypothesis)}`;
  return phase;
}

function formatProgressTimestamp(value: unknown) {
  if (typeof value !== 'string' || !value) return '';
  return formatTime(value);
}

function AffectedPods({ pods }: { pods: string[] }) {
  if (!pods.length) return null;
  const shown = pods.slice(0, 12);
  const remaining = pods.length - shown.length;
  return (
    <div className="affected-pods">
      <span className="affected-pods-label">Affected pods · {pods.length}</span>
      <div className="affected-pods-list">
        {shown.map((pod) => (
          <code key={pod} className="pod-chip" title={pod}>{pod}</code>
        ))}
        {remaining > 0 && <span className="pod-chip pod-chip-more">+{remaining} more</span>}
      </div>
    </div>
  );
}


function DiagnosticsPanel({ missingData, warnings, tokenUsage }: { missingData: string[]; warnings: string[]; tokenUsage?: Record<string, unknown> }) {
  return (
    <section className="diagnostics">
      {tokenUsage && <div className="token-usage">LLM tokens: {formatTokenUsage(tokenUsage)}</div>}
      {missingData.length > 0 && <DiagnosticGroup title="Missing Data" items={missingData} tone="missing" />}
      {warnings.length > 0 && <DiagnosticGroup title="Warnings" items={warnings} tone="warning" />}
    </section>
  );
}

function DiagnosticGroup({
  title,
  items,
  tone,
}: {
  title: string;
  items: string[];
  tone: 'missing' | 'warning';
}) {
  const [open, setOpen] = useState(false);
  const visibleItems = open ? items : items.slice(0, 3);
  const hiddenCount = Math.max(0, items.length - visibleItems.length);

  return (
    <div className={`diagnostic-group diagnostic-${tone}`}>
      <button className="diagnostic-toggle" onClick={() => setOpen((value) => !value)} type="button">
        <span>{title}</span>
        <strong>{items.length}</strong>
        <ChevronDown size={16} />
      </button>
      <ul>
        {visibleItems.map((item, index) => (
          <li key={`${title}-${index}-${item}`}>{item}</li>
        ))}
      </ul>
      {hiddenCount > 0 && (
        <button className="ghost-button compact-button diagnostic-more" onClick={() => setOpen(true)} type="button">
          <ChevronDown size={14} /> Show {hiddenCount} more
        </button>
      )}
    </div>
  );
}

function SimilarIncidentsPanel({ items, recentCount }: { items: SimilarIncident[]; recentCount: number }) {
  const visibleItems = useMemo(
    () =>
      [...items]
        .sort((left, right) => {
          if (right.similarity !== left.similarity) return right.similarity - left.similarity;
          return right.created_at.localeCompare(left.created_at);
        })
        .slice(0, 3),
    [items],
  );
  return (
    <section className="similar-panel">
      <div className="section-title">
        <Search size={18} /> Similar Incidents
        <span className="similar-recent-badge">Recent 7d {recentCount}</span>
      </div>
      {visibleItems.length === 0 ? (
        <p className="empty">No similar incident memory yet.</p>
      ) : (
        <div className="similar-list">
          {visibleItems.map((item) => (
            <article className="similar-item" key={item.incident_id}>
              <div className="similar-head">
                <strong>{item.title || item.incident_id}</strong>
                <span>{Math.round(item.similarity * 100)}%</span>
              </div>
              <div className="meta-line">
                <span>{item.incident_id}</span>
                <Severity value={item.severity} />
                <Status value={item.status} />
                <span>{item.positive_feedback} up</span>
                <span>{item.negative_feedback} down</span>
                <span>{item.comment_count} comments</span>
              </div>
              <p>{item.analysis_summary || 'No prior summary captured.'}</p>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

// Surface WHY a collector is unavailable: match the aggregate missing-data keys and
// warnings back to this agent (keys are prefixed by source, e.g. "system_agent.url",
// "loki.auth", "runai.queue") so an Unavailable card explains itself.
function agentReasons(agent: string, missingData: string[], warnings: string[]): string[] {
  const needles = agent === 'system' ? ['system_agent', 'system'] : [agent];
  const hit = (s: string) => needles.some((n) => s.toLowerCase().includes(n));
  const friendly: Record<string, string> = {
    'system_agent.url': 'System agent is not configured (no URL) — node/kernel evidence was skipped.',
    'system_agent.node': 'No node is associated with this alert — node/kernel evidence was skipped.',
    'loki.auth': 'Loki authentication failed.',
  };
  const fromMissing = missingData.filter(hit).map((k) => friendly[k] || `missing: ${k}`);
  const fromWarnings = warnings.filter(hit);
  return Array.from(new Set([...fromMissing, ...fromWarnings]));
}

// Owner rule: a no-evidence check (e.g. a PASSING DB healthcheck) is not worth
// a card — show only artifacts that actually helped, with the rest behind a
// count the operator can expand.
const NO_EVIDENCE_PREFIX = '증거를 찾기 어렵습니다.';

function isNoEvidenceArtifact(artifact: Artifact) {
  return String(artifact.summary || '').trim().startsWith(NO_EVIDENCE_PREFIX);
}

function AgentEvidence({
  agent,
  status,
  artifacts,
  reasons = [],
}: {
  agent: string;
  status: string;
  artifacts: Artifact[];
  reasons?: string[];
}) {
  const [open, setOpen] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const icon = agentIcon(agent);
  const emptyText = reasons.length > 0 ? reasons.join(' ') : 'No evidence yet.';
  const helpful = artifacts.filter((artifact) => !isNoEvidenceArtifact(artifact));
  const hidden = artifacts.length - helpful.length;
  const visible = showAll ? artifacts : helpful;
  return (
    <article className="agent-evidence">
      <button className="agent-toggle" onClick={() => setOpen((value) => !value)} type="button">
        <span>{icon}</span>
        <strong>{agentLabel(agent)}</strong>
        <Status value={status} />
        <ChevronDown size={16} />
      </button>
      {open && (
        <div className="agent-content">
          {visible.length === 0 ? (
            <p className="empty">{emptyText}</p>
          ) : (
            visible.map((artifact, index) => (
              <ArtifactResult
                artifact={artifact}
                key={`${artifact.agent}-${artifact.type}-${index}`}
              />
            ))
          )}
          {hidden > 0 && (
            <button className="artifact-toggle compact-artifact-toggle" onClick={() => setShowAll((value) => !value)} type="button">
              {showAll ? `Hide ${hidden} no-evidence item(s)` : `Show ${hidden} no-evidence item(s)`}
            </button>
          )}
        </div>
      )}
    </article>
  );
}

function ArtifactResult({ artifact }: { artifact: Artifact }) {
  const [open, setOpen] = useState(false);
  const queryItems = queryDisplayItems(artifact.result);
  const resultText = artifact.result !== undefined ? formatArtifactValue(compactArtifactValue(artifact.result)) : '';
  return (
    <div className="artifact">
      <button className="artifact-toggle compact-artifact-toggle" onClick={() => setOpen((value) => !value)} type="button">
        <div className="artifact-head">
          <strong>{artifact.evidence_id ? `[${artifact.evidence_id}] ` : ''}{artifact.title || artifact.type}</strong>
          <span>{artifact.confidence}</span>
        </div>
        <ChevronDown size={16} />
      </button>
      {open && (
        <div className="artifact-body">
          {/* Emphasis (salient signals) is baked into the summary text as markdown
              bold by the backend, so it also survives Word export / raw JSON — render
              it as markdown instead of overlaying a frontend-only red highlight. */}
          <div className="artifact-summary">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{artifact.summary ?? ''}</ReactMarkdown>
          </div>
          {queryItems.length > 0 ? (
            <QueryResultList items={queryItems} highlights={artifact.highlights} />
          ) : (
            <>
              {artifact.query && <CopyableBlock title="Query" value={artifact.query} kind="code" />}
              {artifact.result !== undefined && !isEmptyResult(artifact.result) && (
                <CopyableBlock
                  title="Result summary"
                  value={resultText}
                  kind="pre"
                  highlights={artifact.highlights}
                />
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function QueryResultList({ items, highlights }: { items: QueryDisplayItem[]; highlights?: string[] }) {
  // A query that came back empty ([]/{}/blank) is noise — drop the whole card, not
  // just its result block, and don't flag it red. Its failure (if any) still shows
  // in the Warnings panel.
  const visible = items.filter((item) => !isEmptyResult(item.preview));
  if (visible.length === 0) return null;
  return (
    <div className="query-result-list">
      {visible.map((item) => (
        <QueryResultCard item={item} key={item.id} highlights={highlights} />
      ))}
    </div>
  );
}

function QueryResultCard({ item, highlights }: { item: QueryDisplayItem; highlights?: string[] }) {
  const previewText = item.preview === undefined ? '' : formatArtifactValue(item.preview);
  const [open, setOpen] = useState(false);
  return (
    <article className="query-result-card">
      <button className="query-result-toggle" onClick={() => setOpen((value) => !value)} type="button">
        <div className="query-result-head">
          <strong>{item.name}</strong>
          <span className={item.status === 'failed' ? 'query-status query-status-error' : 'query-status'}>{item.status}</span>
        </div>
        <ChevronDown size={16} />
      </button>
      {item.facts.length > 0 && (
        <div className="query-facts compact-query-facts">
          {item.facts.slice(0, open ? 4 : 2).map((fact) => (
            <span key={`${item.id}-${fact}`}>{fact}</span>
          ))}
        </div>
      )}
      {open && (
        <>
          {item.queryText && <CopyableBlock title={item.queryLabel} value={item.queryText} kind="code" />}
          {item.preview !== undefined && !isEmptyResult(item.preview) && (
            <CopyableBlock title="Relevant result" value={previewText} kind="pre" highlights={highlights} />
          )}
        </>
      )}
    </article>
  );
}

export default App;
