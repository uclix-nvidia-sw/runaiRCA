import {
  Activity,
  AlertTriangle,
  Archive,
  ArrowLeft,
  Bot,
  BookOpen,
  CheckCircle2,
  ChevronDown,
  CircleStop,
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
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {
  analyzeIncident,
  bulkIncidentAction,
  cancelIncidentAnalysis,
  archiveIncident,
  deleteIncident,
  emptyIncidentTrash,
  fetchAnalysisRun,
  fetchIncident,
  fetchFamilySuggestions,
  fetchRootCauseFamilies,
  rcaCorrection,
  rcaPin,
  reverifyIncident,
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
import { LearnedKnowledgeDashboard } from './dashboards/LearnedKnowledgeDashboard';
import { FeedbackPanel } from './workspace/FeedbackPanel';
import { ConfidenceBreakdownPanel } from './workspace/ConfidenceBreakdownPanel';
import { EvaluationPanel } from './workspace/EvaluationPanel';
import { FloatingChat } from './workspace/FloatingChat';
import { RcaCorrectionPanel } from './workspace/RcaCorrectionPanel';
import { useRcaCorrection } from './workspace/rcaCorrection';
import { useWorkspaceDialog } from './workspace/workspaceDialog';
import { SimilarIncidentsPanel } from './workspace/SimilarIncidentsPanel';
import { useRcaChat } from './workspace/chatSession';
import { exportIncidentDocx } from '../exportDocx';
import { useDashboardData } from '../hooks/useDashboardData';
import { useEditorHistory } from '../hooks/useEditorHistory';
import {
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
import { AlertRecord, AnalysisProgressEntry, AnalysisRun, Artifact, Incident } from '../types';
import { buildAnalysisRecords } from '../utils/analytics';
import { collectorEvidencePresentation, rcaSummaryText, shouldPresentRunArtifacts } from '../utils/analysisPresentation';
import { artifactForPresentation } from '../utils/artifactPresentation';
import { alertFiltersForAPI, incidentFiltersForAPI, incidentViewForMainView, matchesAlertFilters, matchesIncidentFilters } from '../utils/filters';
import { agentTabs, isNoEvidenceArtifact } from '../utils/agentTrail';
import { evidenceState } from '../utils/evidenceState';
import { formatEvidenceQueries, splitRcaReport, stripAppendixEvidence } from '../utils/rcaSections';
import {
  FinalDecision,
  Severity,
  Status,
  agentIcon,
  agentLabel,
  analysisRunDurationMs,
  formatDuration,
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
import { evidenceMetadata, type EvidenceMetadata, type EvidenceWindow } from '../utils/evidenceMetadata';
import { analysisRunForDetail, selectedAnalysisRunID as selectedAnalysisRunIDForDetail } from '../utils/analysisRunSelection';
import { parseCorrectionActions } from '../utils/operatorCorrection';
import {
  compactArtifactValue,
  errorMessage,
  queryDisplayItems,
  reportActionLines,
  safeJSONStringify,
} from '../utils/artifactValues';
import { ProgressTimeline } from './workspace/ProgressTimeline';
import { AffectedPods, AgentTrail, DiagnosticsPanel } from './workspace/EvidenceTrail';
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

function progressForRun(
  run: AnalysisRun | undefined,
  progressByRun: Record<string, AnalysisProgressEntry[]>,
) {
  if (!run) return [];
  if (Object.prototype.hasOwnProperty.call(progressByRun, run.run_id)) {
    return progressByRun[run.run_id] ?? [];
  }
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
  // Failures of destructive incident actions (trash/permanent delete); the
  // dashboard-load `error` above never carries these.
  const [incidentActionError, setIncidentActionError] = useState('');
  const [chatDocked, setChatDocked] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [knowledgeRefreshKey, setKnowledgeRefreshKey] = useState(0);
  const [exactAnalysisRun, setExactAnalysisRun] = useState<AnalysisRun>();
  const detailVersionRef = useRef(0);
  const routeLoadVersionRef = useRef(0);

  // The dedicated Chat view owns the complete conversation surface, including
  // its composer. Leaving the global floating launcher there can cover the
  // send controls (and an open dock leaves stale layout padding), so keep the
  // floating shortcut for every other dashboard only.
  useEffect(() => {
    if (activeView === 'chat') setChatDocked(false);
  }, [activeView]);

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
    return dashboardAnalysisRuns.filter((run) => shouldPresentRunArtifacts(run.status)).flatMap((run) =>
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
          summary: artifact.summary || '증거는 수집되었으나 요약이 제공되지 않았습니다.',
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

  const selectedAnalysisRunID = selectedAnalysisRunIDForDetail(detail);
  const selectedAnalysisRunOnPage = dashboardAnalysisRuns.find((run) => run.run_id === selectedAnalysisRunID);
  const selectedAnalysisAttemptVersion = detail?.kind === 'incident'
    ? `${detail.data.active_analysis_run_id || ''}:${detail.data.is_analyzing}:${detail.data.analysis_hash || ''}`
    : '';
  useEffect(() => {
    let cancelled = false;
    if (!selectedAnalysisRunID) {
      setExactAnalysisRun(undefined);
      return undefined;
    }
    if (selectedAnalysisRunOnPage) {
      setExactAnalysisRun(undefined);
      return undefined;
    }
    setExactAnalysisRun((current) => current?.run_id === selectedAnalysisRunID ? current : undefined);
    void fetchAnalysisRun(selectedAnalysisRunID)
      .then((run) => {
        if (!cancelled) setExactAnalysisRun(run);
      })
      .catch(() => {
        if (!cancelled) setExactAnalysisRun(undefined);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedAnalysisAttemptVersion, selectedAnalysisRunID, selectedAnalysisRunOnPage]);

  const workspaceAnalysisRun = useMemo(
    () => analysisRunForDetail(detail, dashboardAnalysisRuns, exactAnalysisRun),
    [dashboardAnalysisRuns, detail, exactAnalysisRun],
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
  // Analysis and Alerts don't wire the topbar query into their filtering —
  // showing a search box that silently does nothing is worse than no box.
  const searchlessView = activeView === 'analysis' || activeView === 'alerts';

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
      if (activeView === 'knowledge') {
        setKnowledgeRefreshKey((value) => value + 1);
        return;
      }
      await Promise.all([load({ silent: true }), refreshDetail()]);
    } finally {
      setRefreshing(false);
    }
  }, [activeView, load, refreshDetail, refreshing]);

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
    setIncidentActionError('');
    try {
      await deleteIncident(id, permanent);
    } catch (err) {
      setIncidentActionError(errorMessage(err, 'Failed to delete the incident. Check the backend logs.'));
    }
    await refreshCurrentView();
  }, [refreshCurrentView]);

  const handleBulkIncidentAction = useCallback(async (
    incidentIDs: string[],
    action: 'archive' | 'unarchive' | 'restore' | 'trash' | 'delete_permanently',
  ) => {
    setIncidentActionError('');
    try {
      // The backend applies bulk actions best-effort and reports per-row
      // failures; swallowing them made a failed permanent delete look done.
      const result = await bulkIncidentAction(incidentIDs, action);
      const failed = result.failed_ids?.length ?? 0;
      if (failed > 0) {
        setIncidentActionError(
          `${failed} incident${failed === 1 ? '' : 's'} could not be ${action === 'delete_permanently' ? 'permanently deleted' : 'updated'}. Check the backend logs.`,
        );
      }
    } catch (err) {
      setIncidentActionError(errorMessage(err, 'Bulk incident action failed.'));
    }
    await refreshCurrentView();
  }, [refreshCurrentView]);

  const handleEmptyIncidentTrash = useCallback(async () => {
    setIncidentActionError('');
    try {
      const result = await emptyIncidentTrash();
      const failed = result.failed_count ?? 0;
      if (failed > 0) {
        setIncidentActionError(
          `${failed} incident${failed === 1 ? '' : 's'} in trash could not be permanently deleted. Check the backend logs.`,
        );
      }
    } catch (err) {
      setIncidentActionError(errorMessage(err, 'Emptying trash failed.'));
    }
    await refreshCurrentView();
  }, [refreshCurrentView]);

  const chatSession = useRcaChat({
    detail,
    activeView,
    incidents: dashboardIncidents,
    alerts: dashboardAlerts,
    onAnalysisCreated: async () => {
      await load({ silent: true });
    },
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
            className={`nav-item ${activeView === 'knowledge' ? 'active' : ''}`}
            onClick={() => switchView('knowledge')}
            type="button"
          >
            <Database size={18} /> Knowledge
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
          <a
            className="nav-item icon-only-nav-item"
            href="https://uclix.gitbook.io/run-ai-rca-docs"
            target="_blank"
            rel="noreferrer"
            aria-label="Documentation"
            title="Documentation"
          >
            <BookOpen size={18} />
            <span className="sr-only">Documentation</span>
          </a>
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
        <header className={`topbar ${searchlessView ? 'topbar-no-search' : ''}`}>
          <div>
            <p className="eyebrow">{viewCopy.eyebrow}</p>
            <h2>{viewCopy.title}</h2>
          </div>
          {!searchlessView && (
            <div className="search-box">
              <Search size={17} />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder={viewCopy.placeholder}
              />
            </div>
          )}
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
        {incidentActionError && <div className="error-banner">{incidentActionError}</div>}

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
            onBulkAction={handleBulkIncidentAction}
            onEmptyTrash={handleEmptyIncidentTrash}
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
        {activeView === 'knowledge' && (
          <LearnedKnowledgeDashboard query={query} refreshKey={knowledgeRefreshKey} />
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
        onCancel={async (id) => {
          await cancelIncidentAnalysis(id);
          await refreshCurrentView();
        }}
        onReverify={async (id) => {
          await reverifyIncident(id);
          await refreshCurrentView();
        }}
        onOpenIncident={openIncident}
        onResolve={async (id) => {
          await resolveIncident(id);
          await refreshCurrentView();
        }}
      />
      {activeView !== 'chat' && (
        <FloatingChat
          chat={chatSession}
          onDockedChange={setChatDocked}
        />
      )}
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
  onCancel,
  onReverify,
  onOpenIncident,
  onResolve,
}: {
  detail: DetailState;
  analysisRun?: AnalysisRun;
  progressEvents: AnalysisProgressEntry[];
  onClose: () => void;
  onRefresh: () => Promise<void>;
  onAnalyze: (id: string) => Promise<void>;
  onCancel: (id: string) => Promise<void>;
  onReverify: (id: string) => Promise<void>;
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

  const detailKey = detail
    ? detail.kind === 'incident'
      ? detail.data.incident_id
      : detail.data.alert_id
    : null;
  const { closing, justApproved, handleClose, flashApproved, sectionRef } =
    useWorkspaceDialog(detailKey, onClose);

  // Every hook must run before the `if (!detail)` bail-out below: React matches
  // hooks by call order, so one behind a conditional return crashes the panel
  // the moment detail goes null.
  const incident = detail?.kind === 'incident' ? detail.data : null;
  const correction = useRcaCorrection({
    incident,
    analysisRun,
    report: (analysisRun ?? detail?.data ?? {}) as { analysis_summary?: string; analysis_detail?: string },
    busyAction,
    setBusyAction,
    onRefresh,
    onReverify,
  });

  // Opening a different target (or reopening) cancels any in-flight close, so the
  // new detail shows immediately instead of finishing the previous exit animation.

  if (!detail) return null;
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
  const analysisDuration = formatDuration(analysisRunDurationMs(analysisRun));
  const analysis = incident?.analysis_detail;
  const summary = incident?.analysis_summary;
  const isAnalyzing = Boolean(detail.data.is_analyzing);
  const runEvidenceState = evidenceState(
    incident?.missing_data,
    incident?.artifacts?.length ?? 0,
  );
  const evidencePresentation = collectorEvidencePresentation({
    isAnalyzing,
    runStatus: analysisRun?.status,
    firstCompletedAt: analysisRun?.first_completed_at,
    artifactCount: artifacts.length,
  });
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
    <section
      className={`workspace ${closing ? 'is-closing' : ''}`}
      ref={sectionRef}
      tabIndex={-1}
      role="dialog"
      aria-modal="true"
      aria-label={title || `${detail.kind} detail`}
      onKeyDown={(event) => {
        if (event.key !== 'Escape') return;
        // Don't steal Escape from form fields (evaluation notes, comments) —
        // closing the whole dialog mid-edit would discard the operator's text.
        const target = event.target as HTMLElement;
        if (target.closest('input, textarea, select, [contenteditable="true"]')) return;
        event.stopPropagation();
        handleClose();
      }}
    >
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
          <button className="ghost-button" onClick={handleClose} type="button"><ArrowLeft size={16} /> Back</button>
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
                disabled={Boolean(busyAction) || isAnalyzing}
                onClick={() => void runWorkspaceAction('analyze', () => onAnalyze(incident.incident_id))}
                type="button"
              >
                <Bot size={16} /> {busyAction === 'analyze' ? 'Analyzing...' : 'Analyze'}
              </button>
              {isAnalyzing && (
                <button
                  className={`ghost-button ${busyAction === 'cancel' ? 'is-busy' : ''}`}
                  disabled={busyAction === 'cancel'}
                  onClick={() => void runWorkspaceAction('cancel', () => onCancel(incident.incident_id))}
                  type="button"
                >
                  <CircleStop size={16} /> {busyAction === 'cancel' ? 'Stopping...' : 'Stop'}
                </button>
              )}
              <button
                className="ghost-button"
                disabled={Boolean(busyAction) || isAnalyzing}
                onClick={() => correction.setOpen((open) => !open)}
                ref={correction.triggerRef}
                type="button"
              >
                <FileText size={16} /> RCA 수정
              </button>
              {correction.isOperatorRun && (
                <button
                  className={`ghost-button compact-button ${busyAction === 'rca-pin' ? 'is-busy' : ''}`}
                  disabled={Boolean(busyAction)}
                  onClick={() => void correction.togglePin()}
                  type="button"
                >
                  {busyAction === 'rca-pin' ? 'Updating...' : correction.pinned ? '고정 해제' : '고정'}
                </button>
              )}
              {correction.pinned && (
                <button
                  className={`ghost-button compact-button ${busyAction === 'reverify' ? 'is-busy' : ''}`}
                  disabled={Boolean(busyAction)}
                  onClick={() => void correction.reverify()}
                  type="button"
                >
                  <RefreshCw size={14} /> {busyAction === 'reverify' ? 'Analyzing...' : '수정 결론으로 재검증'}
                </button>
              )}
              <button
                className={`ghost-button ${busyAction === 'export' ? 'is-busy' : ''}`}
                disabled={Boolean(busyAction)}
                onClick={() => void runWorkspaceAction('export', () => exportIncidentDocx(incident))}
                type="button"
              >
                <Download size={16} /> {busyAction === 'export' ? 'Exporting...' : 'Export'}
              </button>
              <button
                className={`primary-button ${busyAction === 'resolve' ? 'is-busy' : ''} ${justApproved ? 'just-approved' : ''}`}
                disabled={Boolean(busyAction)}
                onClick={() => void runWorkspaceAction('resolve', async () => {
                  await onResolve(incident.incident_id);
                  flashApproved();
                })}
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
                disabled={Boolean(busyAction) || isAnalyzing}
                onClick={() => void runWorkspaceAction('analyze', () => onAnalyze(alert.incident_id))}
                type="button"
              >
                <Bot size={16} /> {busyAction === 'analyze' ? 'Analyzing...' : 'Analyze'}
              </button>
              {isAnalyzing && (
                <button
                  className={`ghost-button ${busyAction === 'cancel' ? 'is-busy' : ''}`}
                  disabled={busyAction === 'cancel'}
                  onClick={() => void runWorkspaceAction('cancel', () => onCancel(alert.incident_id))}
                  type="button"
                >
                  <CircleStop size={16} /> {busyAction === 'cancel' ? 'Stopping...' : 'Stop'}
                </button>
              )}
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
        {incident && correction.open && (
          <RcaCorrectionPanel correction={correction} busyAction={busyAction} />
        )}
        <section className="rca-summary">
          <div className="rca-summary-heading">
            <h3>RCA Summary</h3>
            {!isAnalyzing && runEvidenceState === 'budget_exhausted' && (
              <span
                className="quality quality-low"
                title="수집기들이 공유 증거 예산 소진으로 스킵되어 이 분석에는 수집된 증거가 없습니다. 재분석을 권장합니다."
              >
                증거 불완전 — 예산 소진
              </span>
            )}
            {!isAnalyzing && runEvidenceState === 'partial' && (
              <span
                className="quality quality-medium"
                title="일부 수집기가 공유 증거 예산 소진으로 스킵되었습니다. 증거가 부분적입니다."
              >
                증거 일부 누락
              </span>
            )}
            {correction.isOperatorRun && (
              <div className="rca-operator-meta">
                <span className="quality quality-operator">운영자 수정</span>
                <span className="rca-operator-pin">{correction.pinned ? '고정됨' : '고정 해제됨'}</span>
              </div>
            )}
          </div>
          <p>{rcaSummaryText(isAnalyzing, summary ?? '')}</p>
          <div className="rca-feedback-strip">
            <span><ThumbsUp size={15} /> {positiveFeedback}</span>
            <span><ThumbsDown size={15} /> {negativeFeedback}</span>
            <span><MessageSquare size={15} /> {commentCount}</span>
            <button className="ghost-button compact-button" onClick={scrollToFeedback} type="button">
              <MessageSquare size={14} /> Feedback
            </button>
          </div>
          {correction.actionError && <p className="feedback-error">{correction.actionError}</p>}
        </section>

        {(isAnalyzing || progressEvents.length > 0) && (
          <ProgressTimeline
            events={progressEvents}
            live={isAnalyzing || analysisRun?.status === 'analyzing'}
            run={analysisRun}
          />
        )}

        {incident && (
          <SimilarIncidentsPanel
            items={similarIncidents}
            recentCount={incident.similar_recent_count ?? 0}
            onOpenIncident={onOpenIncident}
          />
        )}

        <section className="rca-report">
          <div className="section-title"><FileText size={18} /> Report</div>
          {isAnalyzing ? (
            // While a run is in flight the previous report is stale — showing it
            // confused operators into reading the old RCA as the new result.
            <p className="empty">Analyzing… a new RCA report is being generated. The previous report will be replaced when it completes.</p>
          ) : analysis ? (
            // Wrapped so the report fades in when it replaces the "Analyzing…"
            // placeholder (or arrives on open) instead of teleporting in.
            <div className="rca-report-body">
              {(() => {
                const formatted = formatEvidenceQueries(stripAppendixEvidence(analysis));
                const { preamble, sections } = splitRcaReport(formatted);
                if (sections.length === 0) {
                  // ponytail: heading-less report (old runs) renders as before.
                  return <ReactMarkdown remarkPlugins={[remarkGfm]}>{formatted}</ReactMarkdown>;
                }
                return (
                  <>
                    {preamble.trim() && (
                      <div className="rca-preamble">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>{preamble}</ReactMarkdown>
                      </div>
                    )}
                    {sections.map((section, i) =>
                      // Core sections (Problem/Root Cause/Actions) read at a glance —
                      // plain heading + content, no box, no toggle. The rest collapse.
                      section.pinned ? (
                        <section key={i} className="rca-pinned">
                          <h2 className="rca-pinned-heading">{section.heading}</h2>
                          <ReactMarkdown remarkPlugins={[remarkGfm]}>{section.body}</ReactMarkdown>
                        </section>
                      ) : (
                        <details key={i} className="rca-section" open={section.defaultOpen}>
                          <summary>
                            <span>{section.heading}</span>
                            <ChevronDown size={16} className="rca-section-chevron" aria-hidden />
                          </summary>
                          <div className="rca-section-body">
                            <ReactMarkdown remarkPlugins={[remarkGfm]}>{section.body}</ReactMarkdown>
                          </div>
                        </details>
                      ),
                    )}
                  </>
                );
              })()}
            </div>
          ) : (
            <p className="empty">No RCA report yet.</p>
          )}
        </section>

        <section className="agent-trail">
          <div className="section-title"><Bot size={18} /> Collector Evidence Trail</div>
          {evidencePresentation.hidden ? (
            <p className="empty">{evidencePresentation.notice}</p>
          ) : (
            <>
              {evidencePresentation.notice && <p className="empty">{evidencePresentation.notice}</p>}
              <AgentTrail
                key={id}
                artifacts={artifacts}
                capabilities={capabilities}
                missingData={missingData}
                warnings={warnings}
              />
            </>
          )}
        </section>

        {!isAnalyzing && (missingData.length > 0 || warnings.length > 0 || tokenUsage || analysisDuration) && (
          <DiagnosticsPanel missingData={missingData} warnings={warnings} tokenUsage={tokenUsage} analysisDuration={analysisDuration} />
        )}

        {!isAnalyzing && (
          <>
            <ConfidenceBreakdownPanel
              diagnostics={incident?.confidence_diagnostics}
              harness={incident?.harness}
              rootCauseFamily={incident?.root_cause_family}
            />

            <EvaluationPanel
              runID={incident?.analysis_run_id}
              analysisHash={incident?.analysis_hash}
              harness={incident?.harness}
              onSaved={onRefresh}
            />
          </>
        )}

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

export default App;
