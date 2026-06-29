import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Bold,
  Bot,
  CheckCircle2,
  ChevronDown,
  Code2,
  Clipboard,
  Database,
  Eraser,
  FileText,
  Heading3,
  Italic,
  LineChart,
  Link,
  List,
  ListChecks,
  ListOrdered,
  Maximize2,
  MessageSquare,
  Minimize2,
  MoreHorizontal,
  Pencil,
  Redo2,
  RefreshCw,
  Save,
  Search,
  Send,
  Server,
  Settings2,
  ThumbsDown,
  ThumbsUp,
  Trash2,
  Undo2,
  X,
} from 'lucide-react';
import { type KeyboardEvent, type RefObject, Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {
  analyzeIncident,
  addComment,
  chat,
  deleteComment,
  eventSource,
  fetchAnalysisRuns,
  fetchAlert,
  fetchAlerts,
  fetchIncident,
  fetchIncidents,
  resolveIncident,
  submitFeedback,
  updateComment,
  type ChatRequest,
} from './api';
import nvidiaLogo from './assets/nvidia-logo.svg';
import { AlertRecord, AnalysisRun, Artifact, FeedbackSummary, Incident, IncidentDetail, SimilarIncident } from './types';

const TrendChartCanvas = lazy(() => import('./TrendChartCanvas'));

type DetailState =
  | { kind: 'incident'; data: IncidentDetail }
  | { kind: 'alert'; data: AlertRecord }
  | null;

type RealtimeEventPayload = {
  type?: string;
  data?: {
    target_type?: 'incident' | 'alert';
    target_id?: string;
    incident_id?: string;
    alert_id?: string;
  };
};

type EditorTab = 'write' | 'preview';
type MainView = 'incidents' | 'alerts' | 'analysis' | 'agents';
type DetailKind = 'incident' | 'alert';

type RouteState = {
  view: MainView;
  detailKind?: DetailKind;
  detailID?: string;
};

type EvidenceItem = {
  id: string;
  title: string;
  agent: string;
  source: string;
  type: string;
  status: string;
  confidence: string;
  target: string;
  summary: string;
  query?: string;
  result?: unknown;
  alertID?: string;
  incidentID?: string;
  createdAt: string;
};

type AgentSummary = {
  id: string;
  agent: string;
  name: string;
  status: string;
  summary: string;
  source: string;
  lastRun: string;
  evidenceCount: number;
};

type SynthesisSummary = {
  id: string;
  name: string;
  status: string;
  summary: string;
  source: string;
  lastRun: string;
  runCount: number;
};

type AnalysisRecord = {
  id: string;
  incidentID?: string;
  alertID?: string;
  title: string;
  target: string;
  source: string;
  severity: string;
  alertStatus: string;
  analysisStatus: string;
  quality: string;
  summary: string;
  detail: string;
  capabilities: Record<string, string>;
  missingData: string[];
  warnings: string[];
  artifactCount: number;
  similarCount: number;
  positiveFeedback: number;
  negativeFeedback: number;
  commentCount: number;
  createdAt: string;
  isAnalyzing: boolean;
};

type TrendPoint = {
  date: string;
  incidents: number;
  alerts: number;
};

type DistributionItem = {
  key: string;
  count: number;
};

type AnalysisAnalytics = {
  anchorDate: Date;
  summary: {
    totalIncidents: number;
    firingIncidents: number;
    resolvedIncidents: number;
    totalAlerts: number;
    firingAlerts: number;
    resolvedAlerts: number;
    avgMttrMinutes: number;
    avgAlertsPerIncident: number;
    needsEvidence: number;
  };
  series: TrendPoint[];
  breakdown: {
    incidentSeverity: DistributionItem[];
    alertSeverity: DistributionItem[];
    analysisQuality: DistributionItem[];
    topNamespaces: DistributionItem[];
    topQueues: DistributionItem[];
    topProjects: DistributionItem[];
  };
};

const ANALYSIS_AGENT_ID = 'analysis';
const COMPONENT_AGENT_ORDER = ['runai', 'kubernetes', 'postgres', 'prometheus', 'loki'];
const AGENT_ORDER = COMPONENT_AGENT_ORDER;
const ANALYSIS_WINDOWS = [
  { label: '7d', days: 7 },
  { label: '14d', days: 14 },
  { label: '30d', days: 30 },
];
function isCollectorAgent(agent: string) {
  return COMPONENT_AGENT_ORDER.includes(agent);
}

const VIEW_COPY: Record<MainView, { eyebrow: string; title: string; placeholder: string }> = {
  incidents: {
    eyebrow: 'Incident cockpit',
    title: 'Incident',
    placeholder: 'Search incident, severity, status',
  },
  alerts: {
    eyebrow: 'Alert stream',
    title: 'Alerts',
    placeholder: 'Search alert, project, queue, namespace',
  },
  analysis: {
    eyebrow: 'Analysis dashboard',
    title: 'RCA analysis lifecycle',
    placeholder: 'Search RCA, quality, missing data, agent',
  },
  agents: {
    eyebrow: 'Agent registry',
    title: 'Collector and reasoning agents',
    placeholder: 'Search agent, source, status',
  },
};

function routeFromHash(hash: string): RouteState {
  const normalized = hash.replace(/^#\/?/, '').replace(/^\/+/, '');
  if (!normalized) return { view: 'incidents' };
  const [first, second, ...rest] = normalized.split('/');
  const view = first === 'operations' ? 'incidents' : first;
  const collection = second === 'incident' ? 'incidents' : second === 'alert' ? 'alerts' : second;
  if ((isMainView(view) || first === 'operations') && (collection === 'incidents' || collection === 'alerts')) {
    const id = rest.length > 0 ? decodeRoutePart(rest.join('/')) : '';
    if (collection === 'incidents' && id) {
      return { view: isMainView(view) ? view : 'incidents', detailKind: 'incident', detailID: id };
    }
    if (collection === 'alerts' && id) {
      return { view: isMainView(view) ? view : 'alerts', detailKind: 'alert', detailID: id };
    }
  }
  const rawKind = view;
  const id = second ? decodeRoutePart([second, ...rest].join('/')) : '';
  if ((rawKind === 'incidents' || rawKind === 'incident') && id) {
    return { view: 'incidents', detailKind: 'incident', detailID: id };
  }
  if ((rawKind === 'alerts' || rawKind === 'alert') && id) {
    return { view: 'alerts', detailKind: 'alert', detailID: id };
  }
  if (isMainView(rawKind)) {
    return { view: rawKind };
  }
  return { view: 'incidents' };
}

function decodeRoutePart(value: string) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function isMainView(value: string): value is MainView {
  return value === 'incidents' || value === 'alerts' || value === 'analysis' || value === 'agents';
}

function hashForView(view: MainView) {
  return `#/${view}`;
}

function hashForDetail(kind: DetailKind, id: string, view: MainView) {
  const collection = kind === 'incident' ? 'incidents' : 'alerts';
  return `#/${view}/${collection}/${encodeURIComponent(id)}`;
}

function normalizeFeedbackSummary(
  feedback: FeedbackSummary | undefined,
  targetType: 'incident' | 'alert',
  targetID: string,
): FeedbackSummary {
  return {
    target_type: feedback?.target_type || targetType,
    target_id: feedback?.target_id || targetID,
    positive: feedback?.positive ?? 0,
    negative: feedback?.negative ?? 0,
    my_vote: feedback?.my_vote,
    comments: feedback?.comments ?? [],
    learning_hints: feedback?.learning_hints,
  };
}

function errorMessage(err: unknown, fallback: string) {
  return err instanceof Error ? err.message : fallback;
}

function formatArtifactValue(value: unknown) {
  return typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}

async function copyToClipboard(value: string) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // Fall back for local/dev browser contexts where clipboard permission is denied.
    }
  }
  const textarea = document.createElement('textarea');
  textarea.value = value;
  textarea.setAttribute('readonly', 'true');
  textarea.style.position = 'fixed';
  textarea.style.left = '-9999px';
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand('copy');
  document.body.removeChild(textarea);
}

function parseRealtimeEvent(event: Event): RealtimeEventPayload | undefined {
  if (!(event instanceof MessageEvent) || typeof event.data !== 'string') return undefined;
  try {
    return JSON.parse(event.data) as RealtimeEventPayload;
  } catch {
    return undefined;
  }
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

function useEditorHistory(initialValue = '') {
  const [value, setValue] = useState(initialValue);
  const historyRef = useRef<string[]>([initialValue]);
  const indexRef = useRef(0);

  const commit = useCallback((next: string) => {
    const current = historyRef.current[indexRef.current];
    if (next === current) {
      setValue(next);
      return;
    }
    const nextHistory = historyRef.current.slice(0, indexRef.current + 1);
    nextHistory.push(next);
    historyRef.current = nextHistory;
    indexRef.current = nextHistory.length - 1;
    setValue(next);
  }, []);

  const reset = useCallback((next: string) => {
    historyRef.current = [next];
    indexRef.current = 0;
    setValue(next);
  }, []);

  const undo = useCallback(() => {
    if (indexRef.current === 0) return false;
    indexRef.current -= 1;
    setValue(historyRef.current[indexRef.current]);
    return true;
  }, []);

  const redo = useCallback(() => {
    if (indexRef.current >= historyRef.current.length - 1) return false;
    indexRef.current += 1;
    setValue(historyRef.current[indexRef.current]);
    return true;
  }, []);

  return { value, setValue: commit, reset, undo, redo };
}

function useDashboardData() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [analysisRuns, setAnalysisRuns] = useState<AnalysisRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [realtimePayload, setRealtimePayload] = useState<RealtimeEventPayload>();

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    let nextAnalysisRuns: AnalysisRun[] = [];
    try {
      const [incidentData, alertData] = await Promise.all([fetchIncidents(), fetchAlerts()]);
      setIncidents(incidentData);
      setAlerts(alertData);
      try {
        nextAnalysisRuns = await fetchAnalysisRuns();
        setAnalysisRuns(nextAnalysisRuns);
      } catch (err) {
        setAnalysisRuns([]);
        const message = err instanceof Error ? err.message : 'Failed to load analysis runs.';
          setError(`Analysis runs are unavailable: ${message}`);
      }
    } catch (err) {
      setIncidents([]);
      setAlerts([]);
      setAnalysisRuns([]);
      const message = err instanceof Error ? err.message : 'Failed to load dashboard data.';
      setError(message);
    } finally {
      setLoading(false);
    }
  }, []);

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
      void load();
    };
    source.onmessage = handleRealtimeEvent;
    source.addEventListener('alert.created', handleRealtimeEvent);
    source.addEventListener('analysis.started', handleRealtimeEvent);
    source.addEventListener('analysis.completed', handleRealtimeEvent);
    source.addEventListener('incident.resolved', handleRealtimeEvent);
    source.addEventListener('feedback.updated', handleRealtimeEvent);
    return () => source.close();
  }, [load]);

  return {
    incidents,
    alerts,
    analysisRuns,
    loading,
    error,
    load,
    realtimePayload,
  };
}

function App() {
  const {
    incidents,
    alerts,
    analysisRuns,
    loading,
    error,
    load,
    realtimePayload,
  } = useDashboardData();
  const [detail, setDetail] = useState<DetailState>(null);
  const [activeView, setActiveView] = useState<MainView>(() => routeFromHash(window.location.hash).view);
  const [query, setQuery] = useState('');
  const [chatDocked, setChatDocked] = useState(false);
  const detailVersionRef = useRef(0);
  const routeLoadVersionRef = useRef(0);

  useEffect(() => {
    detailVersionRef.current += 1;
  }, [detail]);

  const dashboardIncidents = incidents;
  const dashboardAlerts = alerts;
  const analysisIncidents = incidents;
  const analysisAlerts = alerts;
  const dashboardAnalysisRuns = analysisRuns;

  const filteredIncidents = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return dashboardIncidents;
    return dashboardIncidents.filter((incident) =>
      [incident.title, incident.severity, incident.status, incident.correlation_key]
        .join(' ')
        .toLowerCase()
        .includes(q),
    );
  }, [dashboardIncidents, query]);

  const filteredAlerts = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return dashboardAlerts;
    return dashboardAlerts.filter((alert) =>
      [
        alert.alarm_title,
        alert.severity,
        alert.status,
        alert.labels.project,
        alert.labels.queue,
        alert.labels.workload,
        alert.labels.namespace,
      ]
        .join(' ')
        .toLowerCase()
        .includes(q),
    );
  }, [dashboardAlerts, query]);

  const analysisRecords = useMemo(
    () => buildAnalysisRecords(analysisAlerts, dashboardAnalysisRuns),
    [analysisAlerts, dashboardAnalysisRuns],
  );

  const filteredAnalysis = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return analysisRecords;
    return analysisRecords.filter((record) =>
      [
        record.title,
        record.target,
        record.source,
        record.severity,
        record.alertStatus,
        record.analysisStatus,
        record.quality,
        record.summary,
        record.missingData.join(' '),
        record.warnings.join(' '),
        Object.entries(record.capabilities).map(([agent, status]) => `${agent} ${status}`).join(' '),
      ]
        .join(' ')
        .toLowerCase()
        .includes(q),
    );
  }, [analysisRecords, query]);

  const liveEvidenceItems = useMemo<EvidenceItem[]>(() => {
    return alerts.flatMap((alert) =>
      alert.artifacts
        .filter((artifact) => isCollectorAgent(artifact.agent))
        .map((artifact, index) => ({
          id: `${alert.alert_id}-${artifact.agent}-${artifact.type}-${index}`,
          title: artifact.summary || `${agentLabel(artifact.agent)} ${artifact.type}`,
          agent: artifact.agent,
          source: artifact.source,
          type: artifact.type,
          status: artifact.status || 'ok',
          confidence: artifact.confidence || 'medium',
          target: targetLine(alert.labels),
          summary: artifact.summary || 'Evidence was collected without a summary.',
          query: artifact.query,
          result: artifact.result,
          alertID: alert.alert_id,
          incidentID: alert.incident_id,
          createdAt: alert.fired_at,
        })),
    );
  }, [alerts]);

  const agentSummaries = useMemo<AgentSummary[]>(() => {
    return COMPONENT_AGENT_ORDER.map((agent) => {
      const agentEvidence = latestEvidenceForAgent(liveEvidenceItems, agent);
      const signal = latestAgentSignal(analysisRecords, agentEvidence, agent);
      return {
        id: `agent-${agent}`,
        agent,
        name: `${agentLabel(agent)} Collector`,
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

  const filteredAgents = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return agentSummaries;
    return agentSummaries.filter((agent) =>
      [agent.name, agent.agent, agent.status, agent.summary, agent.source]
        .join(' ')
        .toLowerCase()
        .includes(q),
    );
  }, [agentSummaries, query]);

  const visibleSynthesis = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return synthesisSummary;
    return [synthesisSummary.name, synthesisSummary.status, synthesisSummary.summary, synthesisSummary.source]
      .join(' ')
      .toLowerCase()
      .includes(q)
      ? synthesisSummary
      : null;
  }, [query, synthesisSummary]);

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
      const nextAlert = await fetchAlert(route.detailID);
      if (routeLoadVersionRef.current === version) {
        setDetail({ kind: 'alert', data: nextAlert });
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
    void load();
  };

  const closeDetail = () => navigateToHash(hashForView(activeView));

  const openIncident = useCallback(async (id: string) => {
    navigateToHash(hashForDetail('incident', id, 'incidents'));
  }, [navigateToHash]);

  const openAlert = useCallback(async (id: string) => {
    navigateToHash(hashForDetail('alert', id, 'alerts'));
  }, [navigateToHash]);

  const refreshDetail = useCallback(async () => {
    const currentDetail = detail;
    const version = detailVersionRef.current;
    if (!currentDetail) return;
    if (currentDetail.kind === 'incident') {
      const nextDetail = await fetchIncident(currentDetail.data.incident_id);
      if (detailVersionRef.current === version) {
        setDetail({ kind: 'incident', data: nextDetail });
      }
      return;
    }
    const nextAlert = await fetchAlert(currentDetail.data.alert_id);
    if (detailVersionRef.current === version) {
      setDetail({ kind: 'alert', data: nextAlert });
    }
  }, [detail]);

  const refreshCurrentView = useCallback(async () => {
    await load();
    await refreshDetail();
  }, [load, refreshDetail]);

  useEffect(() => {
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
        <nav>
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
            className={`nav-item ${activeView === 'agents' ? 'active' : ''}`}
            onClick={() => switchView('agents')}
            type="button"
          >
            <Bot size={18} /> Agents
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
          <button className="icon-button" onClick={() => void refreshCurrentView()} aria-label="Refresh">
            <RefreshCw size={18} />
          </button>
        </header>

        {error && <div className="error-banner">{error}</div>}

        {activeView === 'incidents' && (
          <IncidentsDashboard
            incidents={dashboardIncidents}
            filteredIncidents={filteredIncidents}
            loading={loading}
            onOpenIncident={openIncident}
          />
        )}
        {activeView === 'alerts' && (
          <AlertsDashboard
            alerts={dashboardAlerts}
            filteredAlerts={filteredAlerts}
            loading={loading}
            onOpenAlert={openAlert}
            onOpenIncident={openIncident}
          />
        )}
        {activeView === 'analysis' && (
          <AnalysisDashboard
            records={filteredAnalysis}
            allRecords={analysisRecords}
            incidents={analysisIncidents}
            alerts={analysisAlerts}
            totalCount={analysisRecords.length}
            loading={loading}
            onAnalyze={async (id) => {
              await analyzeIncident(id);
              await refreshCurrentView();
            }}
            onOpenAlert={openAlert}
            onOpenIncident={openIncident}
          />
        )}
        {activeView === 'agents' && (
          <AgentsRegistry
            agents={filteredAgents}
            synthesis={visibleSynthesis}
            synthesisRuns={synthesisSummary.runCount}
            totalCount={agentSummaries.length}
          />
        )}
      </main>

      <UnifiedWorkspace
        detail={detail}
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
        detail={detail}
        activeView={activeView}
        incidents={dashboardIncidents}
        alerts={dashboardAlerts}
        onDockedChange={setChatDocked}
        onAnalysisCreated={load}
      />
    </div>
  );
}

function IncidentsDashboard({
  incidents,
  filteredIncidents,
  loading,
  onOpenIncident,
}: {
  incidents: Incident[];
  filteredIncidents: Incident[];
  loading: boolean;
  onOpenIncident: (id: string) => Promise<void>;
}) {
  let openCount = 0;
  let resolvedCount = 0;
  let analyzingIncidentCount = 0;
  for (const i of incidents) {
    if (i.status === 'resolved') resolvedCount++;
    else openCount++;
    if (i.is_analyzing) analyzingIncidentCount++;
  }

  return (
    <>
      <section className="metric-row">
        <Metric label="Open incidents" value={openCount} />
        <Metric label="Total incidents" value={incidents.length} />
        <Metric label="Analyzing" value={analyzingIncidentCount} />
        <Metric label="Resolved incidents" value={resolvedCount} />
      </section>

      <section className="content-grid single-dashboard-grid">
        <div className="panel full-width-panel">
          <PanelHeader title="Incidents" count={filteredIncidents.length} />
          <table className="operations-table incidents-table">
            <thead>
              <tr>
                <th>Incident</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Alerts</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {filteredIncidents.map((incident) => (
                <tr key={incident.incident_id} onClick={() => void onOpenIncident(incident.incident_id)}>
                  <td>
                    <strong>{incident.title}</strong>
                    <span>{incident.incident_id}</span>
                  </td>
                  <td><Severity value={incident.severity} /></td>
                  <td><Status value={incident.status} analyzing={incident.is_analyzing} /></td>
                  <td>{incident.alert_count}</td>
                  <td>{formatTime(incident.fired_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {loading && <p className="empty">Loading incidents...</p>}
          {!loading && filteredIncidents.length === 0 && <p className="empty">No incidents match the current search.</p>}
        </div>
      </section>
    </>
  );
}

function AlertsDashboard({
  alerts,
  filteredAlerts,
  loading,
  onOpenAlert,
  onOpenIncident,
}: {
  alerts: AlertRecord[];
  filteredAlerts: AlertRecord[];
  loading: boolean;
  onOpenAlert: (id: string) => Promise<void>;
  onOpenIncident: (id: string) => Promise<void>;
}) {
  const firingCount = alerts.filter((alert) => alert.status !== 'resolved').length;
  const resolvedCount = alerts.filter((alert) => alert.status === 'resolved').length;
  const analyzingCount = alerts.filter((alert) => alert.is_analyzing).length;

  return (
    <>
      <section className="metric-row">
        <Metric label="Firing alerts" value={firingCount} />
        <Metric label="Total alerts" value={alerts.length} />
        <Metric label="Analyzing" value={analyzingCount} />
        <Metric label="Resolved alerts" value={resolvedCount} />
      </section>

      <section className="content-grid single-dashboard-grid">
        <div className="panel full-width-panel">
          <PanelHeader title="Alerts" count={filteredAlerts.length} />
          <table className="operations-table alerts-table">
            <thead>
              <tr>
                <th>Alert</th>
                <th>Run:AI target</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Incident</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map((alert) => (
                <tr key={alert.alert_id} onClick={() => void onOpenAlert(alert.alert_id)}>
                  <td>
                    <strong>{alert.alarm_title}</strong>
                    <span>{alert.alert_id}</span>
                  </td>
                  <td>
                    <strong>{targetLine(alert.labels)}</strong>
                    <span>{alert.labels.namespace || 'namespace unknown'}</span>
                  </td>
                  <td><Severity value={alert.severity} /></td>
                  <td><Status value={alert.status} analyzing={alert.is_analyzing} /></td>
                  <td>
                    <div className="table-actions">
                      <button
                        className="ghost-button compact-button"
                        onClick={(event) => {
                          event.stopPropagation();
                          void onOpenIncident(alert.incident_id);
                        }}
                        type="button"
                      >
                        <Link size={15} /> Incident
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {loading && <p className="empty">Loading alerts...</p>}
          {!loading && filteredAlerts.length === 0 && <p className="empty">No alerts match the current search.</p>}
        </div>
      </section>
    </>
  );
}

function AnalysisDashboard({
  records,
  allRecords,
  incidents,
  alerts,
  totalCount,
  loading,
  onAnalyze,
  onOpenAlert,
  onOpenIncident,
}: {
  records: AnalysisRecord[];
  allRecords: AnalysisRecord[];
  incidents: Incident[];
  alerts: AlertRecord[];
  totalCount: number;
  loading: boolean;
  onAnalyze: (id: string) => Promise<void>;
  onOpenAlert: (id: string) => Promise<void>;
  onOpenIncident: (id: string) => Promise<void>;
}) {
  const [windowDays, setWindowDays] = useState(14);
  const analytics = useMemo(
    () => buildAnalysisAnalytics(allRecords, incidents, alerts, windowDays),
    [allRecords, alerts, incidents, windowDays],
  );
  const recentRecords = useMemo(
    () => records.filter((record) => isWithinWindow(record.createdAt, windowDays, analytics.anchorDate)),
    [analytics.anchorDate, records, windowDays],
  );
  const completed = allRecords.filter((record) => record.analysisStatus === 'complete').length;
  const highQuality = allRecords.filter((record) => record.quality === 'high').length;

  return (
    <>
      <section className="analysis-toolbar" aria-label="Analysis window">
        <div className="time-window-tabs">
          {ANALYSIS_WINDOWS.map((item) => (
            <button
              className={windowDays === item.days ? 'active' : ''}
              key={item.days}
              onClick={() => setWindowDays(item.days)}
              type="button"
            >
              {item.label}
            </button>
          ))}
        </div>
        <span>{dateRangeLabel(analytics.series)}</span>
      </section>

      <section className="metric-row">
        <Metric label="Incidents" value={analytics.summary.totalIncidents} />
        <Metric label="Alerts" value={analytics.summary.totalAlerts} />
        <Metric label="Avg MTTR" value={formatDurationMinutes(analytics.summary.avgMttrMinutes)} />
        <Metric label="Alerts / Incident" value={formatDecimal(analytics.summary.avgAlertsPerIncident)} />
      </section>

      <section className="analysis-pipeline" aria-label="Collector and synthesis pipeline">
        {COMPONENT_AGENT_ORDER.map((agent) => (
          <PipelineStep
            key={agent}
            agent={agent}
            title={`${agentLabel(agent)} Collector`}
            status={dominantCapability(allRecords, agent)}
          />
        ))}
        <PipelineStep
          agent={ANALYSIS_AGENT_ID}
          synthesis
          title="Analysis Agent"
          status={highQuality > 0 ? 'ok' : completed > 0 ? 'partial' : 'pending'}
        />
      </section>

      <section className="analysis-focus-grid">
        <section className="panel view-panel recent-analysis-panel">
          <PanelHeader title="Recent analyses" count={recentRecords.length} />
          <div className="analysis-list">
            {recentRecords.map((record) => {
              const alertID = record.alertID;
              const incidentID = record.incidentID;
              return (
                <article className="analysis-card" key={record.id}>
                  <div className="analysis-card-head">
                    <div>
                      <div className="section-title compact-title">
                        <ListChecks size={18} />
                        <span>{record.title}</span>
                        <span className={`source-pill source-${analysisSourceClass(record.source)}`}>
                          {sourceLabel(record.source)}
                        </span>
                      </div>
                      <div className="meta-line">
                        <span>{record.alertID || record.id}</span>
                        <span>{record.target}</span>
                        <Severity value={record.severity} />
                        <Status value={record.analysisStatus} />
                      </div>
                    </div>
                    <strong className={`quality quality-${record.quality || 'pending'}`}>{record.quality || 'pending'}</strong>
                  </div>

                  <p className="analysis-summary">
                    {record.summary ||
                      (record.isAnalyzing
                        ? 'Analysis is running. Waiting for new RCA output.'
                        : 'Analysis has not produced a summary yet.')}
                  </p>

                  <div className="coverage-strip">
                    {COMPONENT_AGENT_ORDER.map((agent) => (
                      <span className={`coverage-pill coverage-${record.capabilities[agent] || 'pending'}`} key={agent}>
                        {agentIcon(agent)}
                        <span className="coverage-label">{agentLabel(agent)}</span>
                        <strong>{record.capabilities[agent] || 'pending'}</strong>
                      </span>
                    ))}
                  </div>

                  <div className="analysis-grid">
                    <span>Artifacts <strong>{record.artifactCount}</strong></span>
                    <span>Similar <strong>{record.similarCount}</strong></span>
                    <span>Feedback <strong>{record.positiveFeedback}/{record.negativeFeedback}</strong></span>
                    <span>Comments <strong>{record.commentCount}</strong></span>
                  </div>

                  {(record.missingData.length > 0 || record.warnings.length > 0) && (
                    <div className="analysis-flags">
                      {record.missingData.slice(0, 3).map((item) => (
                        <span key={`missing-${record.id}-${item}`}>{item}</span>
                      ))}
                      {record.warnings.slice(0, 3).map((item) => (
                        <span key={`warning-${record.id}-${item}`}>{item}</span>
                      ))}
                    </div>
                  )}

                  <div className="analysis-actions">
                    <span>{formatTime(record.createdAt)}</span>
                    <div>
                      {alertID && (
                        <button className="ghost-button" onClick={() => void onOpenAlert(alertID)} type="button">
                          <FileText size={16} /> Open report
                        </button>
                      )}
                      {incidentID && (
                        <button className="ghost-button" onClick={() => void onOpenIncident(incidentID)} type="button">
                          <ArrowLeft size={16} /> Incident
                        </button>
                      )}
                      {incidentID && (
                        <button className="primary-button" onClick={() => void onAnalyze(incidentID)} type="button">
                          <Bot size={16} /> Analyze
                        </button>
                      )}
                    </div>
                  </div>
                </article>
              );
            })}
            {loading && <p className="empty">Loading analysis...</p>}
            {!loading && totalCount === 0 && <p className="empty">No analysis records have been created yet.</p>}
            {!loading && totalCount > 0 && recentRecords.length === 0 && <p className="empty">No analyses match the selected time window or search.</p>}
          </div>
        </section>

        <div className="analysis-focus-side">
          <TrendLineChart points={analytics.series} />
          <div className="analysis-side-stack">
            <DistributionBars title="Incident severity" items={analytics.breakdown.incidentSeverity} />
            <DistributionBars title="Analysis quality" items={analytics.breakdown.analysisQuality} />
          </div>
        </div>
      </section>

      <section className="analysis-insight-grid">
        <TopDimensionList title="Top queues" items={analytics.breakdown.topQueues} />
        <TopDimensionList title="Top namespaces" items={analytics.breakdown.topNamespaces} />
        <TopDimensionList title="Top projects" items={analytics.breakdown.topProjects} />
        <AnalysisReadiness records={allRecords} />
      </section>
    </>
  );
}

function TrendLineChart({ points }: { points: TrendPoint[] }) {
  const maxValue = Math.max(1, ...points.map((point) => Math.max(point.incidents, point.alerts)));
  const yTicks = maxValue <= 6 ? Array.from({ length: maxValue + 1 }, (_, index) => index) : undefined;

  return (
    <section className="trend-panel">
      <div className="panel-header compact-panel-header">
        <h3>Incident trend</h3>
        <span>max {maxValue}</span>
      </div>
      <div className="trend-legend">
        <span className="incident-dot">Incidents</span>
        <span className="alert-dot">Alerts</span>
      </div>
      <div className="trend-chart">
        <Suspense fallback={<div className="trend-chart-loading">Loading chart…</div>}>
          <TrendChartCanvas points={points} maxValue={maxValue} yTicks={yTicks} />
        </Suspense>
      </div>
      <div className="trend-bars" style={{ gridTemplateColumns: `repeat(${points.length}, minmax(0, 1fr))` }}>
        {points.map((point) => (
          <div className="trend-bar-group" key={point.date} title={`${point.date}: ${point.incidents} incidents, ${point.alerts} alerts`}>
            <span style={{ height: point.incidents ? `${Math.max((point.incidents / maxValue) * 100, 8)}%` : '0%' }} />
            <span style={{ height: point.alerts ? `${Math.max((point.alerts / maxValue) * 100, 8)}%` : '0%' }} />
          </div>
        ))}
      </div>
    </section>
  );
}

function DistributionBars({ title, items }: { title: string; items: DistributionItem[] }) {
  const max = Math.max(1, ...items.map((item) => item.count));
  return (
    <section className="distribution-panel">
      <div className="compact-panel-title">{title}</div>
      <div className="distribution-list">
        {items.map((item) => (
          <div className="distribution-row" key={item.key || 'unknown'}>
            <span>{item.key || 'unknown'}</span>
            <div><strong style={{ width: `${(item.count / max) * 100}%` }} /></div>
            <b>{item.count}</b>
          </div>
        ))}
        {items.length === 0 && <p className="empty compact-empty">No data</p>}
      </div>
    </section>
  );
}

function TopDimensionList({ title, items }: { title: string; items: DistributionItem[] }) {
  return (
    <section className="top-dimension-panel">
      <div className="compact-panel-title">{title}</div>
      <div className="top-dimension-list">
        {items.map((item) => (
          <div key={item.key || 'unknown'}>
            <span>{item.key || 'unknown'}</span>
            <strong>{item.count}</strong>
          </div>
        ))}
        {items.length === 0 && <p className="empty compact-empty">No data</p>}
      </div>
    </section>
  );
}

function AnalysisReadiness({ records }: { records: AnalysisRecord[] }) {
  return (
    <section className="top-dimension-panel">
      <div className="compact-panel-title">Collector readiness</div>
      <div className="readiness-list">
        {COMPONENT_AGENT_ORDER.map((agent) => {
          const status = dominantCapability(records, agent);
          const okCount = records.filter((record) => record.capabilities[agent] === 'ok').length;
          const width = records.length === 0 ? 0 : (okCount / records.length) * 100;
          return (
            <div className="readiness-row" key={agent}>
              <span>{agentLabel(agent)}</span>
              <div><strong style={{ width: `${width}%` }} /></div>
              <Status value={status} />
            </div>
          );
        })}
      </div>
    </section>
  );
}

function PipelineStep({
  agent,
  title,
  status,
  synthesis = false,
}: {
  agent: string;
  title: string;
  status: string;
  synthesis?: boolean;
}) {
  return (
    <article className={`pipeline-step ${synthesis ? 'synthesis-step' : ''}`}>
      {agentIcon(agent)}
      <div>
        <strong>{title}</strong>
        <Status value={status || 'pending'} />
      </div>
    </article>
  );
}

function AgentsRegistry({
  agents,
  synthesis,
  synthesisRuns,
  totalCount,
}: {
  agents: AgentSummary[];
  synthesis: SynthesisSummary | null;
  synthesisRuns: number;
  totalCount: number;
}) {
  return (
    <>
      <section className="metric-row">
        <Metric label="Collectors" value={totalCount} />
        <Metric label="Collectors ready" value={agents.filter((agent) => agent.status === 'ok').length} />
        <Metric label="Evidence linked" value={agents.reduce((sum, agent) => sum + agent.evidenceCount, 0)} />
        <Metric label="Synthesis runs" value={synthesisRuns} />
      </section>

      <section className="panel view-panel synthesis-panel">
        <PanelHeader title="RCA Synthesis" count={synthesis ? 1 : 0} />
        {synthesis ? (
          <article className="synthesis-card">
            <div className="synthesis-card-head">
              <div className="section-title compact-title">
                {agentIcon(ANALYSIS_AGENT_ID)}
                <span>{synthesis.name}</span>
              </div>
              <Status value={synthesis.status} />
            </div>
            <p>{synthesis.summary}</p>
            <div className="synthesis-stats">
              <span>Source <strong>{synthesis.source}</strong></span>
              <span>Runs <strong>{synthesis.runCount}</strong></span>
              <span>Latest <strong>{formatTime(synthesis.lastRun)}</strong></span>
            </div>
          </article>
        ) : (
          <p className="empty compact-empty">No synthesis run matches the current search.</p>
        )}
      </section>

      <section className="panel view-panel">
        <PanelHeader title="Collectors" count={agents.length} />
        <div className="agent-registry">
          {agents.map((agent) => (
            <article className="agent-card" key={agent.id}>
              <div className="agent-card-head">
                <div className="section-title compact-title">
                  {agentIcon(agent.agent)}
                  <span>{agent.name}</span>
                </div>
                <Status value={agent.status} />
              </div>
              <p>{agent.summary}</p>
              <div className="agent-stats">
                <span>Source <strong>{agent.source}</strong></span>
                <span>Evidence <strong>{agent.evidenceCount}</strong></span>
                <span>Last run <strong>{formatTime(agent.lastRun)}</strong></span>
              </div>
            </article>
          ))}
          {agents.length === 0 && <p className="empty">No collectors match the current search.</p>}
        </div>
      </section>
    </>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function PanelHeader({ title, count }: { title: string; count: number }) {
  return (
    <div className="panel-header">
      <h3>{title}</h3>
      <span>{count}</span>
    </div>
  );
}

function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const timeoutRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (timeoutRef.current !== null) {
        window.clearTimeout(timeoutRef.current);
      }
    };
  }, []);

  const handleClick = useCallback(async () => {
    await copyToClipboard(value);
    setCopied(true);
    if (timeoutRef.current !== null) {
      window.clearTimeout(timeoutRef.current);
    }
    timeoutRef.current = window.setTimeout(() => setCopied(false), 1200);
  }, [value]);

  return (
    <button
      className="copy-button"
      onClick={handleClick}
      type="button"
      title={label}
      aria-label={label}
    >
      {copied ? <CheckCircle2 size={14} /> : <Clipboard size={14} />}
    </button>
  );
}

function CopyableBlock({
  title,
  value,
  kind,
}: {
  title: string;
  value: string;
  kind: 'code' | 'pre';
}) {
  return (
    <div className="copyable-block">
      <div className="copyable-head">{title}</div>
      <div className="copyable-frame">
        <CopyButton value={value} label={`Copy ${title}`} />
        {kind === 'code' ? <code>{value}</code> : <pre>{value}</pre>}
      </div>
    </div>
  );
}

function UnifiedWorkspace({
  detail,
  onClose,
  onRefresh,
  onAnalyze,
  onOpenIncident,
  onResolve,
}: {
  detail: DetailState;
  onClose: () => void;
  onRefresh: () => Promise<void>;
  onAnalyze: (id: string) => Promise<void>;
  onOpenIncident: (id: string) => Promise<void>;
  onResolve: (id: string) => Promise<void>;
}) {
  if (!detail) return null;
  const incident = detail.kind === 'incident' ? detail.data : null;
  const alert = detail.kind === 'alert' ? detail.data : null;
  const title = incident?.title ?? alert?.alarm_title ?? '';
  const id = incident?.incident_id ?? alert?.alert_id ?? '';
  const labels = incident?.alerts[0]?.labels ?? alert?.labels ?? {};
  const artifacts = incident?.artifacts ?? alert?.artifacts ?? [];
  const capabilities = incident?.capabilities ?? alert?.capabilities ?? {};
  const missingData = incident?.missing_data ?? alert?.missing_data ?? [];
  const warnings = incident?.warnings ?? alert?.warnings ?? [];
  const analysis = incident?.analysis_detail ?? alert?.analysis_detail;
  const summary = incident?.analysis_summary ?? alert?.analysis_summary;
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
            <Severity value={detail.data.severity} />
            <Status value={detail.data.status} analyzing={detail.data.is_analyzing} />
          </div>
        </div>
        <div className="workspace-actions">
          <button className="ghost-button" onClick={onClose} type="button"><ArrowLeft size={16} /> Back</button>
          <button className="ghost-button" onClick={() => void onRefresh()} type="button"><RefreshCw size={16} /> Refresh</button>
          {incident && (
            <>
              <button className="ghost-button" onClick={() => void onAnalyze(incident.incident_id)} type="button"><Bot size={16} /> Analyze</button>
              <button className="primary-button" onClick={() => void onResolve(incident.incident_id)} type="button">
                <CheckCircle2 size={16} /> {incident.status === 'resolved' ? 'Reopen' : 'Resolve'}
              </button>
            </>
          )}
          {alert && (
            <>
              <button className="ghost-button" onClick={() => void onOpenIncident(alert.incident_id)} type="button"><Link size={16} /> Incident</button>
              <button className="ghost-button" onClick={() => void onAnalyze(alert.incident_id)} type="button"><Bot size={16} /> Analyze</button>
            </>
          )}
        </div>
      </div>

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

        {incident ? (
          <SimilarIncidentsPanel items={similarIncidents} />
        ) : (
          alert && <RelatedIncidentPanel alert={alert} onOpenIncident={onOpenIncident} />
        )}

        <section className="rca-report">
          <div className="section-title"><FileText size={18} /> Report</div>
          {analysis ? (
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{analysis}</ReactMarkdown>
          ) : (
            <p className="empty">{isAnalyzing ? 'Generating a fresh RCA report...' : 'No RCA report yet.'}</p>
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
              />
            ))}
          </div>
        </section>

        {(missingData.length > 0 || warnings.length > 0) && (
          <section className="diagnostics">
            {missingData.length > 0 && (
              <div>
                <h3>Missing Data</h3>
                <ul>{missingData.map((item) => <li key={item}>{item}</li>)}</ul>
              </div>
            )}
            {warnings.length > 0 && (
              <div>
                <h3>Warnings</h3>
                <ul>{warnings.map((item) => <li key={item}>{item}</li>)}</ul>
              </div>
            )}
          </section>
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

function RelatedIncidentPanel({
  alert,
  onOpenIncident,
}: {
  alert: AlertRecord;
  onOpenIncident: (id: string) => Promise<void>;
}) {
  return (
    <section className="related-panel">
      <div className="section-title"><Link size={18} /> Related Incident</div>
      <article className="related-incident-card">
        <div>
          <strong>{alert.incident_id}</strong>
          <div className="meta-line">
            <span>{targetLine(alert.labels)}</span>
            <Severity value={alert.severity} />
            <Status value={alert.status} analyzing={alert.is_analyzing} />
          </div>
          <p>{alert.analysis_summary || 'This alert is grouped into the incident RCA workspace.'}</p>
        </div>
        <button className="ghost-button" onClick={() => void onOpenIncident(alert.incident_id)} type="button">
          <ArrowLeft size={16} /> Open incident dashboard
        </button>
      </article>
    </section>
  );
}

function SimilarIncidentsPanel({ items }: { items: SimilarIncident[] }) {
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
      <div className="section-title"><Search size={18} /> Similar Incidents</div>
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

function MarkdownEditor({
  value,
  setValue,
  undo,
  redo,
  textareaRef,
  tab,
  onTabChange,
  placeholder,
}: {
  value: string;
  setValue: (value: string) => void;
  undo: () => boolean;
  redo: () => boolean;
  textareaRef: RefObject<HTMLTextAreaElement>;
  tab: EditorTab;
  onTabChange: (tab: EditorTab) => void;
  placeholder: string;
}) {
  const [moreOpen, setMoreOpen] = useState(false);

  const applySelectionTransform = (
    transform: (selected: string) => { text: string; cursorOffset?: number },
  ) => {
    const textarea = textareaRef.current;
    if (!textarea) return;

    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const selected = value.slice(start, end);
    const next = transform(selected);
    const nextPos = start + (next.cursorOffset ?? next.text.length);

    textarea.focus();
    textarea.setRangeText(next.text, start, end, 'end');
    setValue(textarea.value);
    textarea.setSelectionRange(nextPos, nextPos);
  };

  const applyLinePrefix = (prefix: string) => {
    const textarea = textareaRef.current;
    if (!textarea) return;

    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const before = value.slice(0, start);
    const selected = value.slice(start, end);
    const lineStart = before.lastIndexOf('\n') + 1;
    const block = `${value.slice(lineStart, start)}${selected}`;
    const prefixed = block
      .split('\n')
      .map((line) => (line.trim() ? `${prefix}${line}` : line || prefix))
      .join('\n');

    textarea.focus();
    textarea.setRangeText(prefixed, lineStart, end, 'end');
    setValue(textarea.value);
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    const isMod = event.metaKey || event.ctrlKey;
    if (!isMod) return;

    const key = event.key.toLowerCase();
    if (key === 'z') {
      event.preventDefault();
      if (event.shiftKey) redo();
      else undo();
      return;
    }
    if (key === 'y') {
      event.preventDefault();
      redo();
      return;
    }
    if (key === 'b') {
      event.preventDefault();
      applySelectionTransform((text) => ({
        text: `**${text || 'bold text'}**`,
        cursorOffset: text ? undefined : 2,
      }));
      return;
    }
    if (key === 'i') {
      event.preventDefault();
      applySelectionTransform((text) => ({
        text: `*${text || 'italic text'}*`,
        cursorOffset: text ? undefined : 1,
      }));
      return;
    }
    if (key === 'k') {
      event.preventDefault();
      applySelectionTransform((text) => ({
        text: `[${text || 'link text'}](https://example.com)`,
        cursorOffset: text ? undefined : 1,
      }));
      return;
    }
    if (key === 'e') {
      event.preventDefault();
      applySelectionTransform((text) => ({
        text: `\`${text || 'code'}\``,
        cursorOffset: text ? undefined : 1,
      }));
      return;
    }
    if (event.shiftKey && key === 'h') {
      event.preventDefault();
      applyLinePrefix('### ');
    }
  };

  const handleMoreAction = (
    action: 'unordered' | 'numbered' | 'task' | 'mention' | 'reference' | 'slash',
  ) => {
    setMoreOpen(false);
    if (action === 'unordered') {
      applyLinePrefix('- ');
      return;
    }
    if (action === 'numbered') {
      applyLinePrefix('1. ');
      return;
    }
    if (action === 'task') {
      applyLinePrefix('- [ ] ');
      return;
    }
    if (action === 'mention') {
      applySelectionTransform((text) => ({ text: text ? `@${text}` : '@mention' }));
      return;
    }
    if (action === 'reference') {
      applySelectionTransform((text) => ({ text: text ? `${text}#123` : 'owner/repo#123' }));
      return;
    }
    applySelectionTransform((text) => ({ text: text ? `/${text}` : '/command' }));
  };

  const clearEditor = () => {
    setValue('');
    setTimeout(() => {
      const textarea = textareaRef.current;
      if (!textarea) return;
      textarea.focus();
      textarea.setSelectionRange(0, 0);
    }, 0);
  };

  return (
    <div className="comment-editor">
      <div className="editor-tabs">
        <button
          className={tab === 'write' ? 'active' : ''}
          onClick={() => onTabChange('write')}
          type="button"
        >
          Write
        </button>
        <button
          className={tab === 'preview' ? 'active' : ''}
          onClick={() => onTabChange('preview')}
          type="button"
        >
          Preview
        </button>
      </div>

      {tab === 'write' && (
        <div className="editor-toolbar">
          <button type="button" className="editor-tool" onClick={() => applyLinePrefix('### ')} title="Heading" aria-label="Heading">
            <Heading3 size={16} />
          </button>
          <button type="button" className="editor-tool" onClick={() => applySelectionTransform((text) => ({ text: `**${text || 'bold text'}**`, cursorOffset: text ? undefined : 2 }))} title="Bold" aria-label="Bold">
            <Bold size={16} />
          </button>
          <button type="button" className="editor-tool" onClick={() => applySelectionTransform((text) => ({ text: `*${text || 'italic text'}*`, cursorOffset: text ? undefined : 1 }))} title="Italic" aria-label="Italic">
            <Italic size={16} />
          </button>
          <button type="button" className="editor-tool" onClick={() => applySelectionTransform((text) => ({ text: `\`${text || 'code'}\``, cursorOffset: text ? undefined : 1 }))} title="Code" aria-label="Code">
            <Code2 size={16} />
          </button>
          <button type="button" className="editor-tool" onClick={() => applySelectionTransform((text) => ({ text: `[${text || 'link text'}](https://example.com)`, cursorOffset: text ? undefined : 1 }))} title="Link" aria-label="Link">
            <Link size={16} />
          </button>
          <span className="editor-divider" />
          <button type="button" className="editor-tool" onClick={undo} title="Undo" aria-label="Undo">
            <Undo2 size={16} />
          </button>
          <button type="button" className="editor-tool" onClick={redo} title="Redo" aria-label="Redo">
            <Redo2 size={16} />
          </button>
          <div className="editor-more">
            <button type="button" className="editor-tool" onClick={() => setMoreOpen((value) => !value)} title="More" aria-label="More markdown tools">
              <MoreHorizontal size={17} />
            </button>
            {moreOpen && (
              <div className="editor-menu">
                <button type="button" onClick={() => handleMoreAction('unordered')}><List size={15} /> Unordered list</button>
                <button type="button" onClick={() => handleMoreAction('numbered')}><ListOrdered size={15} /> Numbered list</button>
                <button type="button" onClick={() => handleMoreAction('task')}><ListChecks size={15} /> Task list</button>
                <button type="button" onClick={() => handleMoreAction('mention')}>@ Mention</button>
                <button type="button" onClick={() => handleMoreAction('reference')}># Reference</button>
                <button type="button" onClick={() => handleMoreAction('slash')}>/ Command</button>
              </div>
            )}
          </div>
          <button type="button" className="editor-tool editor-clear" onClick={clearEditor} title="Clear" aria-label="Clear editor">
            <Eraser size={16} />
          </button>
        </div>
      )}

      {tab === 'write' ? (
        <textarea
          ref={textareaRef}
          value={value}
          onChange={(event) => setValue(event.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={placeholder}
        />
      ) : (
        <div className="comment-preview">
          {value.trim() ? (
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{value}</ReactMarkdown>
          ) : (
            <p className="empty">Nothing to preview.</p>
          )}
        </div>
      )}
    </div>
  );
}

function FeedbackPanel({
  targetType,
  targetID,
  feedback,
  onSubmitted,
}: {
  targetType: 'incident' | 'alert';
  targetID: string;
  feedback?: FeedbackSummary;
  onSubmitted: () => Promise<void> | void;
}) {
  const [selectedVote, setSelectedVote] = useState<'up' | 'down' | null>(null);
  const [localSummary, setLocalSummary] = useState<FeedbackSummary>(() =>
    normalizeFeedbackSummary(feedback, targetType, targetID),
  );
  const [feedbackError, setFeedbackError] = useState('');
  const draftEditor = useEditorHistory('');
  const comment = draftEditor.value;
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const [editingCommentID, setEditingCommentID] = useState('');
  const editingEditor = useEditorHistory('');
  const editBody = editingEditor.value;
  const editingTextareaRef = useRef<HTMLTextAreaElement>(null);
  const [tab, setTab] = useState<EditorTab>('write');
  const [editingTab, setEditingTab] = useState<EditorTab>('write');
  const [commentMenuID, setCommentMenuID] = useState('');
  const [commentActionID, setCommentActionID] = useState('');
  const [busy, setBusy] = useState(false);
  const summary = localSummary;

  useEffect(() => {
    const nextSummary = normalizeFeedbackSummary(feedback, targetType, targetID);
    setLocalSummary(nextSummary);
    setSelectedVote(nextSummary.my_vote ?? null);
    setFeedbackError('');
  }, [targetType, targetID, feedback]);

  useEffect(() => {
    draftEditor.reset('');
    editingEditor.reset('');
    setEditingCommentID('');
    setCommentMenuID('');
    setCommentActionID('');
    setTab('write');
    setEditingTab('write');
  }, [targetType, targetID]);

  const sendVote = async (vote: 'up' | 'down') => {
    setBusy(true);
    setFeedbackError('');
    try {
      const nextVote = selectedVote === vote ? 'none' : vote;
      const updated = normalizeFeedbackSummary(
        await submitFeedback(targetType, targetID, nextVote),
        targetType,
        targetID,
      );
      setLocalSummary(updated);
      setSelectedVote(updated.my_vote ?? null);
      await onSubmitted();
    } catch (err) {
      setFeedbackError(errorMessage(err, 'Failed to submit vote.'));
    } finally {
      setBusy(false);
    }
  };

  const sendComment = async () => {
    if (!comment.trim()) return;
    setBusy(true);
    setFeedbackError('');
    try {
      const updated = normalizeFeedbackSummary(
        await addComment(targetType, targetID, comment),
        targetType,
        targetID,
      );
      setLocalSummary(updated);
      draftEditor.reset('');
      setTab('write');
      await onSubmitted();
    } catch (err) {
      setFeedbackError(errorMessage(err, 'Failed to add comment.'));
    } finally {
      setBusy(false);
    }
  };

  const saveEdit = async () => {
    if (!editingCommentID || !editBody.trim()) return;
    setBusy(true);
    setFeedbackError('');
    try {
      const updated = normalizeFeedbackSummary(
        await updateComment(targetType, targetID, editingCommentID, editBody),
        targetType,
        targetID,
      );
      setLocalSummary(updated);
      setEditingCommentID('');
      editingEditor.reset('');
      setEditingTab('write');
      await onSubmitted();
    } catch (err) {
      setFeedbackError(errorMessage(err, 'Failed to update comment.'));
    } finally {
      setBusy(false);
    }
  };

  const startEdit = (item: FeedbackSummary['comments'][number]) => {
    setCommentMenuID('');
    setEditingCommentID(item.comment_id);
    editingEditor.reset(item.body);
    setEditingTab('write');
  };

  const removeComment = async (commentID: string) => {
    if (!window.confirm('Delete this comment?')) return;
    setCommentActionID(commentID);
    setFeedbackError('');
    try {
      const updated = normalizeFeedbackSummary(
        await deleteComment(targetType, targetID, commentID),
        targetType,
        targetID,
      );
      setLocalSummary(updated);
      await onSubmitted();
      if (editingCommentID === commentID) {
        setEditingCommentID('');
        editingEditor.reset('');
      }
    } catch (err) {
      setFeedbackError(errorMessage(err, 'Failed to delete comment.'));
    } finally {
      setCommentActionID('');
      setCommentMenuID('');
    }
  };

  return (
    <section className="feedback-panel" id="operator-feedback">
      <div className="section-title"><MessageSquare size={18} /> Operator Feedback</div>
      <div className="feedback-votes">
        <button
          className={`vote-button ${selectedVote === 'up' ? 'selected-up' : ''}`}
          disabled={busy}
          onClick={() => void sendVote('up')}
          aria-label="Upvote"
          type="button"
        >
          <ThumbsUp size={18} />
        </button>
        <strong>{summary.positive}</strong>
        <button
          className={`vote-button ${selectedVote === 'down' ? 'selected-down' : ''}`}
          disabled={busy}
          onClick={() => void sendVote('down')}
          aria-label="Downvote"
          type="button"
        >
          <ThumbsDown size={18} />
        </button>
        <strong>{summary.negative}</strong>
      </div>
      {feedbackError && <p className="feedback-error">{feedbackError}</p>}

      {summary.comments.length > 0 && (
        <div className="comment-list">
          {summary.comments.map((item) => (
            <article className="comment-item" key={item.comment_id}>
              <div className="comment-item-head">
                <div className="comment-author">
                  <span className="comment-avatar">{(item.author || 'O').slice(0, 1).toUpperCase()}</span>
                  <div>
                    <strong>{item.author || 'operator'}</strong>
                    <span>{formatTime(item.created_at)}</span>
                  </div>
                </div>
                <div className="comment-menu-wrap">
                  <button
                    className="comment-menu-button"
                    disabled={commentActionID === item.comment_id}
                    onClick={() => setCommentMenuID((value) => (value === item.comment_id ? '' : item.comment_id))}
                    aria-label="Comment actions"
                    type="button"
                  >
                    <MoreHorizontal size={17} />
                  </button>
                  {commentMenuID === item.comment_id && (
                    <div className="comment-menu">
                      <button type="button" onClick={() => startEdit(item)}><Pencil size={15} /> Edit</button>
                      <button type="button" onClick={() => void removeComment(item.comment_id)}><Trash2 size={15} /> Delete</button>
                    </div>
                  )}
                </div>
              </div>
              {editingCommentID === item.comment_id ? (
                <div className="comment-edit">
                  <MarkdownEditor
                    value={editBody}
                    setValue={editingEditor.setValue}
                    undo={editingEditor.undo}
                    redo={editingEditor.redo}
                    textareaRef={editingTextareaRef}
                    tab={editingTab}
                    onTabChange={setEditingTab}
                    placeholder="Edit RCA comment in markdown"
                  />
                  <div className="comment-tools">
                    <button
                      className="ghost-button"
                      disabled={busy}
                      onClick={() => {
                        setEditingCommentID('');
                        editingEditor.reset('');
                      }}
                      type="button"
                    >
                      <X size={15} /> Cancel
                    </button>
                    <button
                      className="primary-button"
                      disabled={busy || !editBody.trim()}
                      onClick={() => void saveEdit()}
                      type="button"
                    >
                      <Save size={15} /> Save
                    </button>
                  </div>
                </div>
              ) : (
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{item.body}</ReactMarkdown>
              )}
            </article>
          ))}
        </div>
      )}

      <div className="comment-box">
        <MarkdownEditor
          value={comment}
          setValue={draftEditor.setValue}
          undo={draftEditor.undo}
          redo={draftEditor.redo}
          textareaRef={textareaRef}
          tab={tab}
          onTabChange={setTab}
          placeholder={`Add a comment for ${targetType} ${targetID}...`}
        />
        <div className="comment-submit">
          <button className="primary-button" disabled={busy || !comment.trim()} onClick={() => void sendComment()}>
            <Send size={16} /> Comment
          </button>
        </div>
      </div>
    </section>
  );
}

function AgentEvidence({ agent, status, artifacts }: { agent: string; status: string; artifacts: Artifact[] }) {
  const [open, setOpen] = useState(status !== 'pending' || artifacts.length > 0);
  useEffect(() => {
    if (status !== 'pending' || artifacts.length > 0) {
      setOpen(true);
    }
  }, [artifacts.length, status]);
  const icon = agentIcon(agent);
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
          {artifacts.length === 0 ? (
            <p className="empty">No evidence yet.</p>
          ) : (
            artifacts.map((artifact, index) => (
              <ArtifactResult
                artifact={artifact}
                defaultOpen
                key={`${artifact.agent}-${artifact.type}-${index}`}
              />
            ))
          )}
        </div>
      )}
    </article>
  );
}

function ArtifactResult({ artifact, defaultOpen = true }: { artifact: Artifact; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const resultText = artifact.result !== undefined ? formatArtifactValue(artifact.result) : '';
  return (
    <div className="artifact">
      <button className="artifact-toggle compact-artifact-toggle" onClick={() => setOpen((value) => !value)} type="button">
        <div className="artifact-head">
          <strong>{artifact.type}</strong>
          <span>{artifact.confidence}</span>
        </div>
        <ChevronDown size={16} />
      </button>
      {open && (
        <div className="artifact-body">
          <p>{artifact.summary}</p>
          {artifact.query && <CopyableBlock title="Query" value={artifact.query} kind="code" />}
          {artifact.result !== undefined && <CopyableBlock title="Result JSON" value={resultText} kind="pre" />}
        </div>
      )}
    </div>
  );
}

type ChatMessage = {
  id: string;
  role: 'user' | 'assistant';
  content: string;
};

function makeChatMessage(role: ChatMessage['role'], content: string): ChatMessage {
  return {
    id: `${role}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    role,
    content,
  };
}

function FloatingChat({
  detail,
  activeView,
  incidents,
  alerts,
  onDockedChange,
  onAnalysisCreated,
}: {
  detail: DetailState;
  activeView: MainView;
  incidents: Incident[];
  alerts: AlertRecord[];
  onDockedChange: (docked: boolean) => void;
  onAnalysisCreated: () => Promise<void> | void;
}) {
  const [open, setOpen] = useState(false);
  const [docked, setDocked] = useState(false);
  const [showContext, setShowContext] = useState(false);
  const [sending, setSending] = useState(false);
  const [input, setInput] = useState('');
  const [conversationID, setConversationID] = useState('');
  const [manualIncidentID, setManualIncidentID] = useState('');
  const [manualAlertID, setManualAlertID] = useState('');
  const [messages, setMessages] = useState<ChatMessage[]>([
    makeChatMessage('assistant', 'Ask about the current RCA, alert, evidence, or Run:AI workload.'),
  ]);
  const listRef = useRef<HTMLDivElement | null>(null);

  const chatContext = useMemo(
    () => buildChatContext(detail, activeView, incidents, alerts),
    [activeView, alerts, detail, incidents],
  );

  useEffect(() => {
    setManualIncidentID(chatContext.incidentID);
    setManualAlertID(chatContext.alertID);
  }, [chatContext.incidentID, chatContext.alertID]);

  useEffect(() => {
    if (!open || !listRef.current) return;
    listRef.current.scrollTop = listRef.current.scrollHeight;
  }, [messages, open, sending]);

  useEffect(() => {
    onDockedChange(open && docked);
  }, [docked, onDockedChange, open]);

  const send = async () => {
    const message = input.trim();
    if (!message || sending) return;

    const payload: ChatRequest = {
      message,
      conversation_id: conversationID,
      language: 'en',
      page: chatContext.page,
      auto: false,
      incident_id: manualIncidentID.trim() || chatContext.incidentID,
      alert_id: manualAlertID.trim() || chatContext.alertID,
      incident_title: chatContext.incidentTitle,
      incident_content: chatContext.incidentContent,
      alert_title: chatContext.alertTitle,
      alert_content: chatContext.alertContent,
      context: chatContext.context,
    };

    setInput('');
    setMessages((previous) => [...previous, makeChatMessage('user', message)]);
    setSending(true);
    try {
      const response = await chat(payload);
      setConversationID(response.conversation_id || conversationID);
      const answer = response.analysis_run
        ? `${response.answer}\n\nAnalysis run ${response.analysis_run.run_id} was created and added to the Analysis Dashboard.`
        : response.answer;
      setMessages((previous) => [...previous, makeChatMessage('assistant', answer)]);
      if (response.analysis_run) {
        void Promise.resolve(onAnalysisCreated()).catch(() => undefined);
      }
    } catch (error) {
      const text = error instanceof Error ? error.message : 'Chat request failed.';
      setMessages((previous) => [...previous, makeChatMessage('assistant', `Error: ${text}`)]);
    } finally {
      setSending(false);
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      void send();
    }
  };

  return (
    <>
      {open && (
        <section className={`chat-panel ${docked ? 'docked' : ''}`}>
          <header className="chat-header">
            <div>
              <span className="chat-title"><Bot size={17} /> RCA Chat</span>
              <span className="chat-context-line">{chatContext.label}</span>
            </div>
            <div className="chat-actions">
              <button
                onClick={() => setShowContext((value) => !value)}
                aria-label="Edit chat context"
                title="Edit chat context"
                type="button"
              >
                <Settings2 size={16} />
              </button>
              <button
                onClick={() => setDocked((value) => !value)}
                aria-label={docked ? 'Float chat' : 'Dock chat'}
                title={docked ? 'Float chat' : 'Dock chat'}
                type="button"
              >
                {docked ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
              </button>
              <button onClick={() => setOpen(false)} aria-label="Close chat" title="Close chat" type="button">
                <X size={16} />
              </button>
            </div>
          </header>

          {showContext && (
            <div className="chat-context-editor">
              <label>
                Incident
                <input
                  value={manualIncidentID}
                  onChange={(event) => setManualIncidentID(event.target.value)}
                  placeholder="INC-..."
                />
              </label>
              <label>
                Alert
                <input
                  value={manualAlertID}
                  onChange={(event) => setManualAlertID(event.target.value)}
                  placeholder="ALR-..."
                />
              </label>
              <small>Current page and RCA content are attached automatically.</small>
            </div>
          )}

          <div className="chat-messages" ref={listRef}>
            {messages.map((message) => (
              <div className={`chat-message ${message.role}`} key={message.id}>
                {message.role === 'assistant' ? (
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{message.content}</ReactMarkdown>
                ) : (
                  message.content
                )}
              </div>
            ))}
            {sending && <div className="chat-message assistant pending">Analyzing current RCA context...</div>}
          </div>

          <footer className="chat-compose">
            <textarea
              value={input}
              onChange={(event) => setInput(event.target.value)}
              onKeyDown={onKeyDown}
              rows={2}
              placeholder="Ask a follow-up about root cause, evidence, actions, or similar incidents"
            />
            <button className="primary-button" disabled={sending || !input.trim()} onClick={() => void send()}>
              <Send size={16} /> Send
            </button>
          </footer>
        </section>
      )}
      <button className="chat-fab" onClick={() => setOpen((value) => !value)} aria-label="Open chat">
        {open ? <Minimize2 size={22} /> : <MessageSquare size={22} />}
      </button>
    </>
  );
}

function buildChatContext(
  detail: DetailState,
  activeView: MainView,
  incidents: Incident[],
  alerts: AlertRecord[],
) {
  if (detail?.kind === 'incident') {
    const incident = detail.data;
    return {
      page: 'incident_detail',
      label: `Incident ${incident.incident_id}`,
      incidentID: incident.incident_id,
      alertID: '',
      incidentTitle: incident.title,
      incidentContent: incidentChatContent(incident),
      alertTitle: '',
      alertContent: '',
      context: {
        target_type: 'incident',
        incident_id: incident.incident_id,
        severity: incident.severity,
        status: incident.status,
        alerts: incident.alerts.map((alert) => ({
          alert_id: alert.alert_id,
          title: alert.alarm_title,
          status: alert.status,
          severity: alert.severity,
        })),
        capabilities: incident.capabilities,
        missing_data: incident.missing_data,
        warnings: incident.warnings,
        similar_incidents: incident.similar_incidents ?? [],
      },
    };
  }

  if (detail?.kind === 'alert') {
    const alert = detail.data;
    return {
      page: 'alert_detail',
      label: `Alert ${alert.alert_id}`,
      incidentID: alert.incident_id,
      alertID: alert.alert_id,
      incidentTitle: '',
      incidentContent: '',
      alertTitle: alert.alarm_title,
      alertContent: alertChatContent(alert),
      context: {
        target_type: 'alert',
        incident_id: alert.incident_id,
        alert_id: alert.alert_id,
        severity: alert.severity,
        status: alert.status,
        labels: alert.labels,
        annotations: alert.annotations,
        capabilities: alert.capabilities,
        missing_data: alert.missing_data,
        warnings: alert.warnings,
        similar_incidents: alert.similar_incidents ?? [],
      },
    };
  }

  return {
    page: `${activeView}_dashboard`,
    label: `${VIEW_COPY[activeView].title}`,
    incidentID: '',
    alertID: '',
    incidentTitle: '',
    incidentContent: '',
    alertTitle: '',
    alertContent: '',
    context: {
      target_type: 'dashboard',
      active_view: activeView,
      incident_count: incidents.length,
      alert_count: alerts.length,
      open_incidents: incidents.filter((incident) => incident.status !== 'resolved').length,
      firing_alerts: alerts.filter((alert) => alert.status !== 'resolved').length,
      sample_incidents: incidents.slice(0, 5),
      sample_alerts: alerts.slice(0, 5).map((alert) => ({
        alert_id: alert.alert_id,
        incident_id: alert.incident_id,
        title: alert.alarm_title,
        severity: alert.severity,
        status: alert.status,
      })),
    },
  };
}

function incidentChatContent(incident: IncidentDetail) {
  return truncateForChat(
    [
      `Title: ${incident.title}`,
      `Status: ${incident.status}`,
      `Severity: ${incident.severity}`,
      `Summary: ${incident.analysis_summary}`,
      incident.analysis_detail,
      `Missing data: ${incident.missing_data.join(', ') || 'none'}`,
      `Warnings: ${incident.warnings.join(', ') || 'none'}`,
      `Similar incidents: ${(incident.similar_incidents ?? [])
        .map((item) => `${item.incident_id} ${item.analysis_summary}`)
        .join(' | ') || 'none'}`,
    ].join('\n\n'),
  );
}

function alertChatContent(alert: AlertRecord) {
  return truncateForChat(
    [
      `Title: ${alert.alarm_title}`,
      `Status: ${alert.status}`,
      `Severity: ${alert.severity}`,
      `Labels: ${JSON.stringify(alert.labels)}`,
      `Annotations: ${JSON.stringify(alert.annotations)}`,
      `Summary: ${alert.analysis_summary}`,
      alert.analysis_detail,
      `Missing data: ${alert.missing_data.join(', ') || 'none'}`,
      `Warnings: ${alert.warnings.join(', ') || 'none'}`,
    ].join('\n\n'),
  );
}

function truncateForChat(value: string, limit = 8000) {
  if (value.length <= limit) return value;
  return `${value.slice(0, limit)}\n\n[context truncated]`;
}

function buildAnalysisRecords(alerts: AlertRecord[], analysisRuns: AnalysisRun[] = []): AnalysisRecord[] {
  const alertRecords = alerts
    .map((alert) => {
      const hasAnalysis = Boolean(alert.analysis_summary || alert.analysis_detail);
      const analysisStatus = alert.is_analyzing ? 'analyzing' : hasAnalysis ? 'complete' : 'pending';
      const collectorArtifacts = alert.artifacts?.filter((artifact) => isCollectorAgent(artifact.agent)) ?? [];
      return {
        id: `analysis-${alert.alert_id}`,
        incidentID: alert.incident_id,
        alertID: alert.alert_id,
        title: alert.alarm_title || alert.labels.alertname || alert.alert_id,
        target: targetLine(alert.labels),
        source: 'auto',
        severity: alert.severity,
        alertStatus: alert.status,
        analysisStatus,
        quality: alert.analysis_quality || (hasAnalysis ? 'medium' : 'pending'),
        summary: alert.analysis_summary,
        detail: alert.analysis_detail,
        capabilities: alert.capabilities || {},
        missingData: alert.missing_data || [],
        warnings: alert.warnings || [],
        artifactCount: collectorArtifacts.length,
        similarCount: alert.similar_incidents?.length || 0,
        positiveFeedback: alert.feedback?.positive || 0,
        negativeFeedback: alert.feedback?.negative || 0,
        commentCount: alert.feedback?.comments?.length || 0,
        createdAt: alert.fired_at,
        isAnalyzing: alert.is_analyzing,
      };
    })
  const runRecords = analysisRuns.map((run) => ({
    id: run.run_id,
    incidentID: run.incident_id || undefined,
    alertID: run.alert_id || undefined,
    title: run.title || `${sourceLabel(run.source)} analysis`,
    target: `${run.target_type} / ${run.target_id}`,
    source: normalizeAnalysisSource(run.source),
    severity: 'warning',
    alertStatus: run.status,
    analysisStatus: run.status === 'complete' || run.status === 'failed' ? run.status : 'analyzing',
    quality: run.analysis_quality || (run.status === 'failed' ? 'low' : 'pending'),
    summary: run.analysis_summary || run.prompt || 'Analysis request is waiting for agent results.',
    detail: run.analysis_detail,
    capabilities: run.capabilities || {},
    missingData: run.missing_data || [],
    warnings: run.warnings || [],
    artifactCount: run.artifacts?.filter((artifact) => isCollectorAgent(artifact.agent)).length || 0,
    similarCount: 0,
    positiveFeedback: 0,
    negativeFeedback: 0,
    commentCount: 0,
    createdAt: run.created_at,
    isAnalyzing: run.status === 'analyzing',
  }));
  return [...runRecords, ...alertRecords]
    .sort((left, right) => {
      const statusWeight: Record<string, number> = { analyzing: 0, pending: 1, failed: 2, complete: 3 };
      const delta = (statusWeight[left.analysisStatus] ?? 4) - (statusWeight[right.analysisStatus] ?? 4);
      if (delta !== 0) return delta;
      return right.createdAt.localeCompare(left.createdAt);
    });
}

function sourceLabel(source: string) {
  switch (normalizeAnalysisSource(source)) {
    case 'auto':
      return 'Auto';
    case 'manual':
      return 'Manual';
    case 'comment':
      return 'Comment';
    case 'feedback':
      return 'Feedback';
    case 'chat':
      return 'Chat';
    default:
      return 'RCA';
  }
}

function normalizeAnalysisSource(source: string) {
  if (['auto', 'manual', 'comment', 'feedback', 'chat'].includes(source)) {
    return source;
  }
  return 'manual';
}

function analysisSourceClass(source: string) {
  return normalizeAnalysisSource(source);
}

function buildAnalysisAnalytics(
  records: AnalysisRecord[],
  incidents: Incident[],
  alerts: AlertRecord[],
  windowDays: number,
): AnalysisAnalytics {
  const anchorDate = startOfUtcDay(new Date());
  const windowedIncidents = incidents.filter((incident) =>
    isActiveWithinWindow(incident.fired_at, incident.resolved_at ?? '', incident.status, windowDays, anchorDate),
  );
  const windowedAlerts = alerts.filter((alert) =>
    isActiveWithinWindow(alert.fired_at, alert.resolved_at ?? '', alert.status, windowDays, anchorDate),
  );
  const windowedRecords = records.filter((record) => isWithinWindow(record.createdAt, windowDays, anchorDate));
  const resolvedDurations = windowedIncidents
    .map((incident) => durationMinutes(incident.fired_at, incident.resolved_at ?? ''))
    .filter((value) => value > 0);
  const totalAlerts = windowedAlerts.length;
  const totalIncidents = windowedIncidents.length;

  return {
    anchorDate,
    summary: {
      totalIncidents,
      firingIncidents: windowedIncidents.filter((incident) => incident.status !== 'resolved').length,
      resolvedIncidents: windowedIncidents.filter((incident) => incident.status === 'resolved').length,
      totalAlerts,
      firingAlerts: windowedAlerts.filter((alert) => alert.status !== 'resolved').length,
      resolvedAlerts: windowedAlerts.filter((alert) => alert.status === 'resolved').length,
      avgMttrMinutes: average(resolvedDurations),
      avgAlertsPerIncident: totalIncidents === 0 ? 0 : totalAlerts / totalIncidents,
      needsEvidence: windowedRecords.filter((record) => record.missingData.length > 0 || record.warnings.length > 0).length,
    },
    series: buildDailySeries(windowedIncidents, windowedAlerts, windowDays, anchorDate),
    breakdown: {
      incidentSeverity: countBy(windowedIncidents, (incident) => incident.severity || 'unknown'),
      alertSeverity: countBy(windowedAlerts, (alert) => alert.severity || 'unknown'),
      analysisQuality: countBy(windowedRecords, (record) => record.quality || 'pending'),
      topNamespaces: countBy(windowedAlerts, (alert) => alert.labels.namespace || 'unknown').slice(0, 5),
      topQueues: countBy(windowedAlerts, (alert) => alert.labels.queue || alert.labels.runai_queue || 'unknown').slice(0, 5),
      topProjects: countBy(windowedAlerts, (alert) => alert.labels.project || alert.labels.runai_project || 'unknown').slice(0, 5),
    },
  };
}

function buildDailySeries(
  incidents: Incident[],
  alerts: AlertRecord[],
  windowDays: number,
  anchorDate: Date,
): TrendPoint[] {
  // Precompute day boundaries once to avoid repeated date construction in the inner loop
  const days = Array.from({ length: windowDays }).map((_, index) => {
    const date = addUtcDays(anchorDate, index - windowDays + 1);
    const dayStart = startOfUtcDay(date);
    const dayEnd = addUtcDays(dayStart, 1);
    return { date: dateKey(date), dayStart, dayEnd };
  });

  const points: TrendPoint[] = days.map(({ date }) => ({ date, incidents: 0, alerts: 0 }));

  // Parse each record's timestamps once (outside the inner loop) then do pure date comparisons
  incidents.forEach((incident) => {
    const started = parseDate(incident.fired_at);
    if (!started) return;
    const ended = activeEndDate(incident.fired_at, incident.resolved_at ?? '', incident.status);
    days.forEach(({ dayStart, dayEnd }, i) => {
      if (started < dayEnd && (!ended || ended >= dayStart)) {
        points[i].incidents += 1;
      }
    });
  });

  alerts.forEach((alert) => {
    const started = parseDate(alert.fired_at);
    if (!started) return;
    const ended = activeEndDate(alert.fired_at, alert.resolved_at ?? '', alert.status);
    days.forEach(({ dayStart, dayEnd }, i) => {
      if (started < dayEnd && (!ended || ended >= dayStart)) {
        points[i].alerts += 1;
      }
    });
  });

  return points;
}

function countBy<T>(items: T[], getKey: (item: T) => string): DistributionItem[] {
  const counts = new Map<string, number>();
  items.forEach((item) => {
    const key = getKey(item) || 'unknown';
    counts.set(key, (counts.get(key) ?? 0) + 1);
  });
  return [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((left, right) => {
      if (right.count !== left.count) return right.count - left.count;
      return left.key.localeCompare(right.key);
    });
}

function latestEvidenceForAgent(items: EvidenceItem[], agent: string) {
  return items
    .filter((item) => item.agent === agent)
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
}

function latestAgentSignal(records: AnalysisRecord[], evidenceItems: EvidenceItem[], agent: string) {
  const capability = latestCapabilitySignal(records, agent);
  const evidence = evidenceItems[0];
  if (capability && (!evidence || capability.createdAt.localeCompare(evidence.createdAt) >= 0)) {
    return {
      status: capability.status,
      source: `${agent}.collector`,
      lastRun: capability.createdAt || '-',
    };
  }
  if (evidence) {
    return {
      status: normalizeAgentStatus(evidence.status) || 'pending',
      source: evidence.source || `${agent}.collector`,
      lastRun: evidence.createdAt || '-',
    };
  }
  return {
    status: 'pending',
    source: `${agent}.collector`,
    lastRun: '-',
  };
}

function latestCapabilitySignal(records: AnalysisRecord[], agent: string) {
  const signals = records
    .map((record) => ({
      status: normalizeAgentStatus(record.capabilities[agent]),
      createdAt: record.createdAt,
    }))
    .filter((item) => item.status)
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  if (signals.length === 0) return null;
  const latestAt = signals[0].createdAt;
  return {
    status: worstAgentStatus(signals.filter((item) => item.createdAt === latestAt).map((item) => item.status)),
    createdAt: latestAt,
  };
}

function normalizeAgentStatus(value?: string) {
  const status = (value || '').trim().toLowerCase();
  if (!status) return '';
  if (['ok', 'complete', 'completed', 'success', 'ready'].includes(status)) return 'ok';
  if (['failed', 'failure', 'error', 'unavailable', 'down'].includes(status)) return 'unavailable';
  if (['partial', 'degraded', 'warning'].includes(status)) return 'partial';
  if (['running', 'analyzing', 'in_progress'].includes(status)) return 'analyzing';
  if (status === 'pending') return 'pending';
  return status;
}

function worstAgentStatus(statuses: string[]) {
  return statuses
    .map((status) => normalizeAgentStatus(status))
    .filter(Boolean)
    .sort((left, right) => agentStatusRank(right) - agentStatusRank(left))[0] || 'pending';
}

function agentStatusRank(status: string) {
  switch (normalizeAgentStatus(status)) {
    case 'unavailable':
      return 4;
    case 'partial':
      return 3;
    case 'analyzing':
      return 2;
    case 'pending':
      return 1;
    case 'ok':
      return 0;
    default:
      return 1;
  }
}

function uniqueStrings(items: string[]) {
  return [...new Set(items.filter(Boolean))];
}

function isWithinWindow(value: string, windowDays: number, anchorDate: Date) {
  const parsed = parseDate(value);
  if (!parsed) return false;
  const start = addUtcDays(anchorDate, -windowDays + 1);
  const day = startOfUtcDay(parsed);
  return day >= start && day <= anchorDate;
}

function isActiveWithinWindow(
  startedAt: string,
  resolvedAt: string,
  status: string,
  windowDays: number,
  anchorDate: Date,
) {
  const started = parseDate(startedAt);
  if (!started) return false;
  const windowStart = addUtcDays(anchorDate, -windowDays + 1);
  const windowEnd = addUtcDays(anchorDate, 1);
  const ended = activeEndDate(startedAt, resolvedAt, status);
  return started < windowEnd && (!ended || ended >= windowStart);
}

function isActiveOnDay(startedAt: string, resolvedAt: string, status: string, day: Date) {
  const started = parseDate(startedAt);
  if (!started) return false;
  const dayStart = startOfUtcDay(day);
  const dayEnd = addUtcDays(dayStart, 1);
  const ended = activeEndDate(startedAt, resolvedAt, status);
  return started < dayEnd && (!ended || ended >= dayStart);
}

function activeEndDate(startedAt: string, resolvedAt: string, status: string) {
  const resolved = parseDate(resolvedAt);
  if (resolved) return resolved;
  if (status === 'resolved') return parseDate(startedAt);
  return null;
}

function durationMinutes(start: string, end: string) {
  const startDate = parseDate(start);
  const endDate = parseDate(end);
  if (!startDate || !endDate) return 0;
  return Math.max(0, Math.round((endDate.getTime() - startDate.getTime()) / 60000));
}

function average(values: number[]) {
  if (values.length === 0) return 0;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function parseDate(value: string) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function startOfUtcDay(date: Date) {
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
}

function addUtcDays(date: Date, days: number) {
  const next = new Date(date);
  next.setUTCDate(next.getUTCDate() + days);
  return next;
}

function dateKey(date: Date) {
  return date.toISOString().slice(0, 10);
}

function dateRangeLabel(points: TrendPoint[]) {
  if (points.length === 0) return '-';
  return `${points[0].date} - ${points[points.length - 1].date}`;
}

function formatDurationMinutes(value: number) {
  if (!value) return '0m';
  if (value < 60) return `${Math.round(value)}m`;
  const hours = value / 60;
  return `${formatDecimal(hours)}h`;
}

function formatDecimal(value: number) {
  return value.toFixed(1);
}

function dominantCapability(records: AnalysisRecord[], agent: string) {
  return latestCapabilitySignal(records, agent)?.status || 'pending';
}

function Severity({ value }: { value: string }) {
  return <span className={`severity severity-${value || 'warning'}`}>{value || 'warning'}</span>;
}

function Status({ value, analyzing = false }: { value: string; analyzing?: boolean }) {
  const displayValue = analyzing ? 'analyzing' : (value || 'pending');
  return <span className={`status status-${displayValue}`}>{displayValue}</span>;
}

function targetLine(labels: Record<string, string>) {
  const project = labels.project || labels.runai_project || 'project unknown';
  const queue = labels.queue || labels.runai_queue || 'queue unknown';
  const workload = labels.workload || labels.workload_name || labels.pod || 'workload unknown';
  return `${project} / ${queue} / ${workload}`;
}

function formatTime(value: string) {
  if (!value) return '-';
  return value.replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}

function agentLabel(agent: string) {
  const labels: Record<string, string> = {
    analysis: 'Analysis',
    runai: 'Run:AI',
    kubernetes: 'Kubernetes',
    postgres: 'Postgres',
    prometheus: 'Prometheus',
    loki: 'Loki',
  };
  return labels[agent] || agent;
}

function agentIcon(agent: string) {
  if (agent === 'analysis') return <ListChecks size={18} />;
  if (agent === 'runai') return <Activity size={18} />;
  if (agent === 'kubernetes') return <Server size={18} />;
  if (agent === 'postgres') return <Database size={18} />;
  if (agent === 'prometheus') return <LineChart size={18} />;
  if (agent === 'loki') return <FileText size={18} />;
  return <AlertTriangle size={18} />;
}

export default App;
