import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Bold,
  Bot,
  CheckCircle2,
  ChevronDown,
  Code2,
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
import { type KeyboardEvent, type RefObject, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import {
  CartesianGrid,
  Line,
  LineChart as RechartsLineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import remarkGfm from 'remark-gfm';
import {
  analyzeIncident,
  addComment,
  chat,
  deleteComment,
  eventSource,
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
import { AlertRecord, Artifact, FeedbackSummary, Incident, IncidentDetail, SimilarIncident } from './types';

type DetailState =
  | { kind: 'incident'; data: IncidentDetail }
  | { kind: 'alert'; data: AlertRecord }
  | null;

type EditorTab = 'write' | 'preview';
type MainView = 'operations' | 'analysis' | 'evidence' | 'agents';

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
  mock?: boolean;
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
  mock?: boolean;
};

type AnalysisRecord = {
  id: string;
  incidentID: string;
  alertID: string;
  title: string;
  target: string;
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
  mock?: boolean;
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
const AGENT_REGISTRY_ORDER = [ANALYSIS_AGENT_ID, ...COMPONENT_AGENT_ORDER];
const ANALYSIS_WINDOWS = [
  { label: '7d', days: 7 },
  { label: '14d', days: 14 },
  { label: '30d', days: 30 },
];
const ENABLE_MOCK_DATA = runtimeBool('enableMockData', 'VITE_ENABLE_MOCK_DATA', import.meta.env.DEV);
const MOCK_EVIDENCE_ITEM: EvidenceItem = {
  id: 'mock-evidence-runai-queue',
  title: 'Sample Run:AI queue snapshot',
  agent: 'runai',
  source: 'mock.runai.queue',
  type: 'queue-snapshot',
  status: 'ok',
  confidence: 'high',
  target: 'vision / gpu-a / trainer',
  summary: 'Mock evidence: workload trainer is pending because gpu-a quota is exhausted.',
  query: 'GET /api/v1/workloads?project=vision&queue=gpu-a&name=trainer',
  result: {
    queue: 'gpu-a',
    requested_gpus: 4,
    allocated_gpus: 0,
    reason: 'GPU quota exhausted',
  },
  createdAt: '2026-06-26T00:00:00Z',
  mock: true,
};
const MOCK_AGENT_SUMMARY: AgentSummary = {
  id: 'mock-agent-runai',
  agent: 'runai',
  name: 'Run:AI Collector',
  status: 'ok',
  summary: 'Mock agent run: validates Run:AI workload state, queue pressure, and quota signals.',
  source: 'mock.agent.runai',
  lastRun: '2026-06-26T00:00:00Z',
  evidenceCount: 1,
  mock: true,
};
const MOCK_ANALYSIS_AGENT_SUMMARY: AgentSummary = {
  id: 'mock-agent-analysis',
  agent: ANALYSIS_AGENT_ID,
  name: 'Analysis Agent',
  status: 'ok',
  summary: 'Mock analysis agent: combines component evidence into the RCA report and dashboard state.',
  source: 'mock.agent.analysis',
  lastRun: '2026-06-26T00:00:00Z',
  evidenceCount: 1,
  mock: true,
};
const MOCK_ALERT_ARTIFACT: Artifact = {
  agent: 'runai',
  source: 'mock.runai.queue',
  type: 'queue-snapshot',
  status: 'ok',
  confidence: 'high',
  query: 'GET /api/v1/workloads?project=vision&queue=gpu-a&name=trainer',
  summary: 'Mock evidence: workload trainer is pending because gpu-a quota is exhausted.',
  result: {
    queue: 'gpu-a',
    requested_gpus: 4,
    allocated_gpus: 0,
    reason: 'GPU quota exhausted',
  },
};
const MOCK_INCIDENT: Incident = {
  incident_id: 'MOCK-INC-000001',
  correlation_key: 'mock/runai/queue/gpu-a/trainer',
  title: 'Mock GPU workload pending on Run:AI queue',
  severity: 'warning',
  status: 'firing',
  fired_at: '2026-06-26T00:00:00Z',
  resolved_at: null,
  alert_count: 1,
  is_analyzing: false,
};
const MOCK_ALERT: AlertRecord = {
  alert_id: 'MOCK-ALR-000001',
  incident_id: MOCK_INCIDENT.incident_id,
  alarm_title: 'Mock Run:AI workload pending',
  severity: 'warning',
  status: 'firing',
  fired_at: MOCK_INCIDENT.fired_at,
  resolved_at: null,
  fingerprint: 'mock-runai-workload-pending',
  thread_ts: 'mock-thread',
  labels: {
    namespace: 'runai',
    project: 'vision',
    queue: 'gpu-a',
    workload: 'trainer',
  },
  annotations: {
    summary: 'Mock workload is pending while waiting for GPU quota.',
  },
  analysis_summary: 'Mock RCA: gpu-a quota is exhausted, so the workload cannot be scheduled.',
  analysis_detail:
    '## Root Cause\n\nMock Run:AI queue `gpu-a` has no available GPU quota for workload `trainer`.\n\n## Recommended Actions\n\nIncrease queue quota or move the workload to a queue with available GPUs.',
  analysis_quality: 'mock',
  capabilities: {
    runai: 'ok',
    kubernetes: 'pending',
    postgres: 'ok',
    prometheus: 'pending',
    loki: 'pending',
  },
  missing_data: ['live cluster connection'],
  warnings: ['Mock data is shown because the Operations dashboard has no live incidents or alerts yet.'],
  artifacts: [MOCK_ALERT_ARTIFACT],
  similar_incidents: [],
  feedback: {
    target_type: 'alert',
    target_id: 'MOCK-ALR-000001',
    positive: 0,
    negative: 0,
    comments: [],
  },
  is_analyzing: false,
};
const MOCK_INCIDENT_DETAIL: IncidentDetail = {
  ...MOCK_INCIDENT,
  analysis_summary: MOCK_ALERT.analysis_summary,
  analysis_detail: MOCK_ALERT.analysis_detail,
  analysis_quality: MOCK_ALERT.analysis_quality,
  capabilities: MOCK_ALERT.capabilities,
  missing_data: MOCK_ALERT.missing_data,
  warnings: MOCK_ALERT.warnings,
  artifacts: MOCK_ALERT.artifacts,
  similar_incidents: [],
  feedback: {
    target_type: 'incident',
    target_id: 'MOCK-INC-000001',
    positive: 0,
    negative: 0,
    comments: [],
  },
  alerts: [MOCK_ALERT],
};
const MOCK_ANALYTICS_INCIDENTS: Incident[] = [
  MOCK_INCIDENT,
  makeMockIncident({
    id: 'MOCK-INC-000002',
    correlationKey: 'mock/runai/queue/gpu-a/batch-trainer',
    title: 'Recurring gpu-a queue saturation',
    severity: 'warning',
    status: 'resolved',
    firedAt: '2026-06-25T09:30:00Z',
    resolvedAt: '2026-06-25T10:05:00Z',
    alertCount: 2,
  }),
  makeMockIncident({
    id: 'MOCK-INC-000003',
    correlationKey: 'mock/runai-backend/scheduler/reconcile-lag',
    title: 'Run:AI scheduler reconciliation lag',
    severity: 'critical',
    status: 'resolved',
    firedAt: '2026-06-24T03:20:00Z',
    resolvedAt: '2026-06-24T04:08:00Z',
    alertCount: 3,
  }),
  makeMockIncident({
    id: 'MOCK-INC-000004',
    correlationKey: 'mock/runai/queue/gpu-b/eval-worker',
    title: 'GPU node capacity pressure delayed pods',
    severity: 'warning',
    status: 'resolved',
    firedAt: '2026-06-22T13:10:00Z',
    resolvedAt: '2026-06-22T14:00:00Z',
    alertCount: 1,
  }),
  makeMockIncident({
    id: 'MOCK-INC-000005',
    correlationKey: 'mock/runai/project/cv/image-pull',
    title: 'Image pull delay during CV workload startup',
    severity: 'info',
    status: 'resolved',
    firedAt: '2026-06-20T18:00:00Z',
    resolvedAt: '2026-06-20T18:18:00Z',
    alertCount: 1,
  }),
  makeMockIncident({
    id: 'MOCK-INC-000006',
    correlationKey: 'mock/postgres/rca-memory/write-latency',
    title: 'RCA memory write latency increased',
    severity: 'warning',
    status: 'resolved',
    firedAt: '2026-06-18T01:40:00Z',
    resolvedAt: '2026-06-18T02:21:00Z',
    alertCount: 1,
  }),
];
const MOCK_ANALYTICS_ALERTS: AlertRecord[] = [
  MOCK_ALERT,
  makeMockAlert({
    id: 'MOCK-ALR-000002',
    incidentID: 'MOCK-INC-000002',
    title: 'Mock Run:AI queue gpu-a saturation',
    severity: 'warning',
    status: 'resolved',
    firedAt: '2026-06-25T09:30:00Z',
    resolvedAt: '2026-06-25T10:05:00Z',
    labels: { namespace: 'runai', project: 'vision', queue: 'gpu-a', workload: 'batch-trainer' },
    quality: 'high',
    summary: 'Queue gpu-a requested GPUs exceeded allocatable quota for two training workloads.',
    capabilities: { runai: 'ok', kubernetes: 'ok', postgres: 'ok', prometheus: 'ok', loki: 'partial' },
    artifacts: 4,
  }),
  makeMockAlert({
    id: 'MOCK-ALR-000003',
    incidentID: 'MOCK-INC-000003',
    title: 'Mock Run:AI backend scheduler lag',
    severity: 'critical',
    status: 'resolved',
    firedAt: '2026-06-24T03:20:00Z',
    resolvedAt: '2026-06-24T04:08:00Z',
    labels: { namespace: 'runai-backend', project: 'platform', queue: 'gpu-platform', workload: 'scheduler' },
    quality: 'high',
    summary: 'Scheduler reconciliation lag aligned with runai-backend warning logs and pending workload growth.',
    capabilities: { runai: 'partial', kubernetes: 'ok', postgres: 'ok', prometheus: 'ok', loki: 'ok' },
    artifacts: 5,
    warnings: ['scheduler log window was sampled'],
  }),
  makeMockAlert({
    id: 'MOCK-ALR-000004',
    incidentID: 'MOCK-INC-000003',
    title: 'Mock pending workload burst',
    severity: 'warning',
    status: 'resolved',
    firedAt: '2026-06-24T03:36:00Z',
    resolvedAt: '2026-06-24T04:08:00Z',
    labels: { namespace: 'runai', project: 'platform', queue: 'gpu-platform', workload: 'inference-burst' },
    quality: 'medium',
    summary: 'Pending workloads increased while scheduler reconciliation was delayed.',
    capabilities: { runai: 'ok', kubernetes: 'ok', postgres: 'ok', prometheus: 'partial', loki: 'ok' },
    artifacts: 3,
  }),
  makeMockAlert({
    id: 'MOCK-ALR-000005',
    incidentID: 'MOCK-INC-000004',
    title: 'Mock GPU node allocatable pressure',
    severity: 'warning',
    status: 'resolved',
    firedAt: '2026-06-22T13:10:00Z',
    resolvedAt: '2026-06-22T14:00:00Z',
    labels: { namespace: 'runai', project: 'research', queue: 'gpu-b', workload: 'eval-worker' },
    quality: 'medium',
    summary: 'GPU node allocatable capacity was lower than queued pod requests during the alert window.',
    capabilities: { runai: 'ok', kubernetes: 'ok', postgres: 'ok', prometheus: 'partial', loki: 'pending' },
    artifacts: 3,
    missingData: ['loki.workload_logs'],
  }),
  makeMockAlert({
    id: 'MOCK-ALR-000006',
    incidentID: 'MOCK-INC-000005',
    title: 'Mock image pull delay',
    severity: 'info',
    status: 'resolved',
    firedAt: '2026-06-20T18:00:00Z',
    resolvedAt: '2026-06-20T18:18:00Z',
    labels: { namespace: 'runai-cv', project: 'cv', queue: 'gpu-c', workload: 'preprocess' },
    quality: 'medium',
    summary: 'Image pull latency caused a short startup delay before the workload recovered.',
    capabilities: { runai: 'ok', kubernetes: 'ok', postgres: 'ok', prometheus: 'pending', loki: 'ok' },
    artifacts: 2,
  }),
  makeMockAlert({
    id: 'MOCK-ALR-000007',
    incidentID: 'MOCK-INC-000006',
    title: 'Mock RCA memory write latency',
    severity: 'warning',
    status: 'resolved',
    firedAt: '2026-06-18T01:40:00Z',
    resolvedAt: '2026-06-18T02:21:00Z',
    labels: { namespace: 'runai-rca', project: 'ops', queue: 'control-plane', workload: 'backend' },
    quality: 'low',
    summary: 'Postgres write latency affected RCA memory persistence but did not block alert analysis.',
    capabilities: { runai: 'pending', kubernetes: 'ok', postgres: 'partial', prometheus: 'ok', loki: 'partial' },
    artifacts: 3,
    missingData: ['postgres.pg_stat_statements'],
  }),
];
const VIEW_COPY: Record<MainView, { eyebrow: string; title: string; placeholder: string }> = {
  operations: {
    eyebrow: 'Incident cockpit',
    title: 'GPU workload RCA workspace',
    placeholder: 'Search project, queue, workload, status',
  },
  analysis: {
    eyebrow: 'Analysis dashboard',
    title: 'RCA analysis lifecycle',
    placeholder: 'Search RCA, quality, missing data, agent',
  },
  evidence: {
    eyebrow: 'Evidence inventory',
    title: 'Collected RCA evidence',
    placeholder: 'Search evidence, agent, source, target',
  },
  agents: {
    eyebrow: 'Agent registry',
    title: 'Collector and reasoning agents',
    placeholder: 'Search agent, source, status',
  },
};

function makeMockIncident({
  id,
  correlationKey,
  title,
  severity,
  status,
  firedAt,
  resolvedAt,
  alertCount,
}: {
  id: string;
  correlationKey: string;
  title: string;
  severity: string;
  status: string;
  firedAt: string;
  resolvedAt: string | null;
  alertCount: number;
}): Incident {
  return {
    incident_id: id,
    correlation_key: correlationKey,
    title,
    severity,
    status,
    fired_at: firedAt,
    resolved_at: resolvedAt,
    alert_count: alertCount,
    is_analyzing: false,
  };
}

function makeMockAlert({
  id,
  incidentID,
  title,
  severity,
  status,
  firedAt,
  resolvedAt,
  labels,
  quality,
  summary,
  capabilities,
  artifacts,
  missingData = [],
  warnings = [],
}: {
  id: string;
  incidentID: string;
  title: string;
  severity: string;
  status: string;
  firedAt: string;
  resolvedAt: string | null;
  labels: Record<string, string>;
  quality: string;
  summary: string;
  capabilities: Record<string, string>;
  artifacts: number;
  missingData?: string[];
  warnings?: string[];
}): AlertRecord {
  return {
    alert_id: id,
    incident_id: incidentID,
    alarm_title: title,
    severity,
    status,
    fired_at: firedAt,
    resolved_at: resolvedAt,
    fingerprint: id.toLowerCase(),
    thread_ts: `mock-${id.toLowerCase()}`,
    labels,
    annotations: {
      summary,
    },
    analysis_summary: summary,
    analysis_detail: [
      '## Root Cause',
      '',
      summary,
      '',
      '## Evidence',
      '',
      '- Mock evidence follows the same shape as live Run:AI RCA collector artifacts.',
      '',
      '## Recommended Actions',
      '',
      '- Confirm queue, pod, metric, log, and persistence evidence before taking action.',
    ].join('\n'),
    analysis_quality: quality,
    capabilities,
    missing_data: missingData,
    warnings,
    artifacts: Array.from({ length: artifacts }).map((_, index) => ({
      agent: COMPONENT_AGENT_ORDER[index % COMPONENT_AGENT_ORDER.length],
      source: `mock.${COMPONENT_AGENT_ORDER[index % COMPONENT_AGENT_ORDER.length]}`,
      type: 'analysis-signal',
      status: index === 0 ? 'ok' : 'partial',
      confidence: index <= 1 ? 'high' : 'medium',
      summary: `${agentLabel(COMPONENT_AGENT_ORDER[index % COMPONENT_AGENT_ORDER.length])} mock signal for ${title}.`,
      result: { incident_id: incidentID, alert_id: id, signal_index: index + 1 },
    })),
    similar_incidents: [],
    feedback: mockFeedback('alert', id),
    is_analyzing: false,
  };
}

function mockFeedback(targetType: 'incident' | 'alert', targetID: string): FeedbackSummary {
  return {
    target_type: targetType,
    target_id: targetID,
    positive: 0,
    negative: 0,
    comments: [],
  };
}

function runtimeBool(runtimeKey: 'enableMockData', envKey: string, fallback: boolean) {
  const runtimeValue = window.__RUNAI_RCA_CONFIG__?.[runtimeKey];
  if (typeof runtimeValue === 'boolean') return runtimeValue;
  const envValue = import.meta.env[envKey];
  if (envValue === undefined) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(envValue).trim().toLowerCase());
}

function mockAlertDetail(id: string) {
  return MOCK_ANALYTICS_ALERTS.find((alert) => alert.alert_id === id) ?? null;
}

function mockIncidentDetail(id: string): IncidentDetail | null {
  if (id === MOCK_INCIDENT.incident_id) return MOCK_INCIDENT_DETAIL;
  const incident = MOCK_ANALYTICS_INCIDENTS.find((item) => item.incident_id === id);
  if (!incident) return null;
  const incidentAlerts = MOCK_ANALYTICS_ALERTS.filter((alert) => alert.incident_id === id);
  const firstAlert = incidentAlerts[0];
  return {
    ...incident,
    analysis_summary: firstAlert?.analysis_summary ?? '',
    analysis_detail: incidentAlerts.map((alert) => alert.analysis_detail).filter(Boolean).join('\n\n---\n\n'),
    analysis_quality: firstAlert?.analysis_quality ?? 'pending',
    capabilities: mergeCapabilities(incidentAlerts.map((alert) => alert.capabilities)),
    missing_data: uniqueStrings(incidentAlerts.flatMap((alert) => alert.missing_data)),
    warnings: uniqueStrings(incidentAlerts.flatMap((alert) => alert.warnings)),
    artifacts: incidentAlerts.flatMap((alert) => alert.artifacts),
    similar_incidents: [],
    feedback: mockFeedback('incident', id),
    alerts: incidentAlerts,
  };
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

function App() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [detail, setDetail] = useState<DetailState>(null);
  const [activeView, setActiveView] = useState<MainView>('operations');
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setError('');
    try {
      const [incidentData, alertData] = await Promise.all([fetchIncidents(), fetchAlerts()]);
      setIncidents(incidentData);
      setAlerts(alertData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load dashboard data.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    const source = eventSource();
    source.onmessage = () => void load();
    source.addEventListener('alert.created', () => void load());
    source.addEventListener('analysis.completed', () => void load());
    source.addEventListener('incident.resolved', () => void load());
    source.addEventListener('feedback.updated', () => void load());
    return () => source.close();
  }, [load]);

  const showMockData = ENABLE_MOCK_DATA && !loading && !error && incidents.length === 0 && alerts.length === 0;
  const operationIncidents = showMockData ? [MOCK_INCIDENT] : incidents;
  const operationAlerts = showMockData ? [MOCK_ALERT] : alerts;
  const analysisIncidents = showMockData ? MOCK_ANALYTICS_INCIDENTS : incidents;
  const analysisAlerts = showMockData ? MOCK_ANALYTICS_ALERTS : alerts;

  const filteredIncidents = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return operationIncidents;
    return operationIncidents.filter((incident) =>
      [incident.title, incident.severity, incident.status, incident.correlation_key]
        .join(' ')
        .toLowerCase()
        .includes(q),
    );
  }, [operationIncidents, query]);

  const filteredAlerts = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return operationAlerts;
    return operationAlerts.filter((alert) =>
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
  }, [operationAlerts, query]);

  const analysisRecords = useMemo(() => buildAnalysisRecords(analysisAlerts), [analysisAlerts]);

  const filteredAnalysis = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return analysisRecords;
    return analysisRecords.filter((record) =>
      [
        record.title,
        record.target,
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
      alert.artifacts.map((artifact, index) => ({
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

  const evidenceItems = liveEvidenceItems.length > 0 ? liveEvidenceItems : showMockData ? [MOCK_EVIDENCE_ITEM] : [];

  const filteredEvidence = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return evidenceItems;
    return evidenceItems.filter((item) =>
      [item.title, item.agent, item.source, item.type, item.status, item.confidence, item.target, item.summary]
        .join(' ')
        .toLowerCase()
        .includes(q),
    );
  }, [evidenceItems, query]);

  const agentSummaries = useMemo<AgentSummary[]>(() => {
    if (liveEvidenceItems.length === 0 && showMockData) return [MOCK_ANALYSIS_AGENT_SUMMARY, MOCK_AGENT_SUMMARY];
    return AGENT_REGISTRY_ORDER.map((agent) => {
      if (agent === ANALYSIS_AGENT_ID) {
        const latest = analysisRecords[0];
        return {
          id: `agent-${agent}`,
          agent,
          name: 'Analysis Agent',
          status: analysisRecords.some((record) => record.isAnalyzing)
            ? 'analyzing'
            : analysisRecords.some((record) => record.detail || record.summary)
              ? 'ok'
              : 'pending',
          summary:
            analysisRecords.length > 0
              ? `${analysisRecords.length} RCA analysis record(s) tracked across current alerts.`
              : 'No RCA analysis records have been created yet.',
          source: 'nemo.analysis_agent',
          lastRun: latest?.createdAt || '-',
          evidenceCount: analysisRecords.length,
        };
      }
      const agentEvidence = liveEvidenceItems.filter((item) => item.agent === agent);
      const latest = agentEvidence[0];
      return {
        id: `agent-${agent}`,
        agent,
        name: `${agentLabel(agent)} Agent`,
        status: agentEvidence.length > 0 ? 'ok' : 'pending',
        summary:
          agentEvidence.length > 0
            ? `${agentEvidence.length} evidence item(s) collected for recent RCA context.`
            : 'No evidence has been collected by this agent yet.',
        source: latest?.source || `${agent}.collector`,
        lastRun: latest?.createdAt || '-',
        evidenceCount: agentEvidence.length,
      };
    });
  }, [analysisRecords, liveEvidenceItems, showMockData]);

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

  const viewCopy = VIEW_COPY[activeView];

  const openIncident = async (id: string) => {
    if (showMockData) {
      const mockDetail = mockIncidentDetail(id);
      if (mockDetail) {
        setDetail({ kind: 'incident', data: mockDetail });
        return;
      }
    }
    setDetail({ kind: 'incident', data: await fetchIncident(id) });
  };

  const openAlert = async (id: string) => {
    if (showMockData) {
      const mockAlert = mockAlertDetail(id);
      if (mockAlert) {
        setDetail({ kind: 'alert', data: mockAlert });
        return;
      }
    }
    setDetail({ kind: 'alert', data: await fetchAlert(id) });
  };

  const refreshDetail = async () => {
    if (!detail) return;
    if (showMockData && detail.kind === 'incident') {
      const mockDetail = mockIncidentDetail(detail.data.incident_id);
      if (mockDetail) {
        setDetail({ kind: 'incident', data: mockDetail });
        return;
      }
    }
    if (showMockData && detail.kind === 'alert') {
      const mockAlert = mockAlertDetail(detail.data.alert_id);
      if (mockAlert) {
        setDetail({ kind: 'alert', data: mockAlert });
        return;
      }
    }
    if (detail.kind === 'incident') {
      setDetail({ kind: 'incident', data: await fetchIncident(detail.data.incident_id) });
      return;
    }
    setDetail({ kind: 'alert', data: await fetchAlert(detail.data.alert_id) });
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <img className="brand-logo" src={nvidiaLogo} alt="NVIDIA" />
        <div>
          <p className="eyebrow">NVIDIA Run:ai</p>
          <h1>Run:AI RCA</h1>
        </div>
        <nav>
          <button
            className={`nav-item ${activeView === 'operations' ? 'active' : ''}`}
            onClick={() => setActiveView('operations')}
            type="button"
          >
            <Activity size={18} /> Operations
          </button>
          <button
            className={`nav-item ${activeView === 'analysis' ? 'active' : ''}`}
            onClick={() => setActiveView('analysis')}
            type="button"
          >
            <ListChecks size={18} /> Analysis
          </button>
          <button
            className={`nav-item ${activeView === 'evidence' ? 'active' : ''}`}
            onClick={() => setActiveView('evidence')}
            type="button"
          >
            <Database size={18} /> Evidence
          </button>
          <button
            className={`nav-item ${activeView === 'agents' ? 'active' : ''}`}
            onClick={() => setActiveView('agents')}
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
          <button className="icon-button" onClick={() => void load()} aria-label="Refresh">
            <RefreshCw size={18} />
          </button>
        </header>

        {error && <div className="error-banner">{error}</div>}

        {activeView === 'operations' && (
          <OperationsView
            incidents={operationIncidents}
            alerts={operationAlerts}
            filteredIncidents={filteredIncidents}
            filteredAlerts={filteredAlerts}
            loading={loading}
            onOpenIncident={openIncident}
            onOpenAlert={openAlert}
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
              await load();
            }}
            onOpenAlert={openAlert}
            onOpenIncident={openIncident}
          />
        )}
        {activeView === 'evidence' && (
          <EvidenceInventory
            items={filteredEvidence}
            totalCount={evidenceItems.length}
            onOpenAlert={openAlert}
          />
        )}
        {activeView === 'agents' && (
          <AgentsRegistry
            agents={filteredAgents}
            totalCount={agentSummaries.length}
          />
        )}
      </main>

      <UnifiedWorkspace
        detail={detail}
        onClose={() => setDetail(null)}
        onRefresh={() => void refreshDetail()}
        onAnalyze={async (id) => {
          await analyzeIncident(id);
          await refreshDetail();
        }}
        onResolve={async (id) => {
          await resolveIncident(id);
          await refreshDetail();
          await load();
        }}
      />
      <FloatingChat
        detail={detail}
        activeView={activeView}
        incidents={operationIncidents}
        alerts={operationAlerts}
      />
    </div>
  );
}

function OperationsView({
  incidents,
  alerts,
  filteredIncidents,
  filteredAlerts,
  loading,
  onOpenIncident,
  onOpenAlert,
}: {
  incidents: Incident[];
  alerts: AlertRecord[];
  filteredIncidents: Incident[];
  filteredAlerts: AlertRecord[];
  loading: boolean;
  onOpenIncident: (id: string) => Promise<void>;
  onOpenAlert: (id: string) => Promise<void>;
}) {
  return (
    <>
      <section className="metric-row">
        <Metric label="Open incidents" value={incidents.filter((i) => i.status !== 'resolved').length} />
        <Metric label="Alerts" value={alerts.length} />
        <Metric
          label="Analyzing"
          value={alerts.filter((alert) => alert.is_analyzing).length + incidents.filter((i) => i.is_analyzing).length}
        />
        <Metric label="Postgres agent" value="Ready" />
      </section>

      <section className="content-grid">
        <div className="panel">
          <PanelHeader title="Incidents" count={filteredIncidents.length} />
          <table>
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
        </div>

        <div className="panel">
          <PanelHeader title="Alerts" count={filteredAlerts.length} />
          <table>
            <thead>
              <tr>
                <th>Alert</th>
                <th>Run:AI target</th>
                <th>Severity</th>
                <th>Status</th>
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
                </tr>
              ))}
            </tbody>
          </table>
          {!loading && filteredAlerts.length === 0 && <p className="empty">No alerts yet.</p>}
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
  const highQuality = allRecords.filter((record) => ['high', 'mock'].includes(record.quality)).length;

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

      <section className="analysis-pipeline" aria-label="Analysis agent pipeline">
        <PipelineStep agent={ANALYSIS_AGENT_ID} title="Analysis Agent" status={highQuality > 0 ? 'ok' : completed > 0 ? 'partial' : 'pending'} />
        {COMPONENT_AGENT_ORDER.map((agent) => (
          <PipelineStep
            key={agent}
            agent={agent}
            title={`${agentLabel(agent)} Agent`}
            status={dominantCapability(records, agent)}
          />
        ))}
      </section>

      <section className="analysis-overview-grid">
        <TrendLineChart points={analytics.series} />
        <div className="analysis-side-stack">
          <DistributionBars title="Incident severity" items={analytics.breakdown.incidentSeverity} />
          <DistributionBars title="Analysis quality" items={analytics.breakdown.analysisQuality} />
        </div>
      </section>

      <section className="analysis-insight-grid">
        <TopDimensionList title="Top queues" items={analytics.breakdown.topQueues} />
        <TopDimensionList title="Top namespaces" items={analytics.breakdown.topNamespaces} />
        <TopDimensionList title="Top projects" items={analytics.breakdown.topProjects} />
        <AnalysisReadiness records={allRecords} />
      </section>

      <section className="panel view-panel">
        <PanelHeader title="Recent analyses" count={recentRecords.length} />
        <div className="analysis-list">
          {recentRecords.map((record) => (
            <article className="analysis-card" key={record.id}>
              <div className="analysis-card-head">
                <div>
                  <div className="section-title compact-title">
                    <ListChecks size={18} />
                    <span>{record.title}</span>
                    {record.mock && <span className="sample-pill">Mock</span>}
                  </div>
                  <div className="meta-line">
                    <span>{record.alertID}</span>
                    <span>{record.target}</span>
                    <Severity value={record.severity} />
                    <Status value={record.analysisStatus} />
                  </div>
                </div>
                <strong className={`quality quality-${record.quality || 'pending'}`}>{record.quality || 'pending'}</strong>
              </div>

              <p className="analysis-summary">
                {record.summary || 'Analysis has not produced a summary yet.'}
              </p>

              <div className="coverage-strip">
                {COMPONENT_AGENT_ORDER.map((agent) => (
                  <span className={`coverage-pill coverage-${record.capabilities[agent] || 'pending'}`} key={agent}>
                    {agentIcon(agent)}
                    {agentLabel(agent)}
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
                  <button className="ghost-button" onClick={() => void onOpenAlert(record.alertID)} type="button">
                    <FileText size={16} /> Open report
                  </button>
                  <button className="ghost-button" onClick={() => void onOpenIncident(record.incidentID)} type="button">
                    <ArrowLeft size={16} /> Incident
                  </button>
                  <button className="primary-button" onClick={() => void onAnalyze(record.incidentID)} type="button">
                    <Bot size={16} /> Analyze
                  </button>
                </div>
              </div>
            </article>
          ))}
          {loading && <p className="empty">Loading analysis...</p>}
          {!loading && recentRecords.length === 0 && <p className="empty">No matching analysis records.</p>}
        </div>
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
        <ResponsiveContainer width="100%" height="100%">
          <RechartsLineChart data={points} margin={{ top: 10, right: 16, bottom: 4, left: 0 }}>
            <CartesianGrid stroke="#e5e7eb" vertical={false} />
            <XAxis
              dataKey="date"
              axisLine={false}
              tickLine={false}
              tickFormatter={formatTrendTick}
              interval="preserveStartEnd"
              minTickGap={18}
            />
            <YAxis
              allowDecimals={false}
              axisLine={false}
              tickLine={false}
              ticks={yTicks}
              width={30}
              domain={[0, maxValue]}
            />
            <Tooltip
              contentStyle={{
                border: '1px solid #e5e7eb',
                borderRadius: '0.45rem',
                boxShadow: '0 14px 30px rgba(16, 24, 40, 0.12)',
              }}
              cursor={{ stroke: '#94a3b8', strokeDasharray: '4 4' }}
              labelFormatter={(label) => `Date ${label}`}
            />
            <Line
              type="monotone"
              dataKey="incidents"
              name="Incidents"
              stroke="#4b7f00"
              strokeWidth={3}
              dot={{ r: 4, strokeWidth: 2, fill: '#4b7f00', stroke: '#ffffff' }}
              activeDot={{ r: 6, strokeWidth: 2, fill: '#4b7f00', stroke: '#ffffff' }}
              isAnimationActive={false}
            />
            <Line
              type="monotone"
              dataKey="alerts"
              name="Alerts"
              stroke="#f59e0b"
              strokeWidth={3}
              dot={{ r: 4, strokeWidth: 2, fill: '#f59e0b', stroke: '#ffffff' }}
              activeDot={{ r: 6, strokeWidth: 2, fill: '#f59e0b', stroke: '#ffffff' }}
              isAnimationActive={false}
            />
          </RechartsLineChart>
        </ResponsiveContainer>
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

function formatTrendTick(value: string) {
  return value.slice(5);
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
      <div className="compact-panel-title">Agent readiness</div>
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

function PipelineStep({ agent, title, status }: { agent: string; title: string; status: string }) {
  return (
    <article className="pipeline-step">
      {agentIcon(agent)}
      <div>
        <strong>{title}</strong>
        <Status value={status || 'pending'} />
      </div>
    </article>
  );
}

function EvidenceInventory({
  items,
  totalCount,
  onOpenAlert,
}: {
  items: EvidenceItem[];
  totalCount: number;
  onOpenAlert: (id: string) => Promise<void>;
}) {
  const mockCount = items.filter((item) => item.mock).length;
  return (
    <>
      <section className="metric-row">
        <Metric label="Evidence items" value={totalCount} />
        <Metric label="Visible" value={items.length} />
        <Metric label="Mock samples" value={mockCount} />
        <Metric label="High confidence" value={items.filter((item) => item.confidence === 'high').length} />
      </section>

      <section className="panel view-panel">
        <PanelHeader title="Evidence" count={items.length} />
        <div className="evidence-list">
          {items.map((item) => (
            <article className="evidence-card" key={item.id}>
              <div className="evidence-card-head">
                <div>
                  <div className="section-title compact-title">
                    {agentIcon(item.agent)}
                    <span>{item.title}</span>
                    {item.mock && <span className="sample-pill">Mock</span>}
                  </div>
                  <div className="meta-line">
                    <span>{agentLabel(item.agent)}</span>
                    <span>{item.source}</span>
                    <span>{item.target}</span>
                    <Status value={item.status} />
                  </div>
                </div>
                <strong className="confidence">{item.confidence}</strong>
              </div>
              <p>{item.summary}</p>
              {item.query && <code>{item.query}</code>}
              {item.result !== undefined && <pre>{JSON.stringify(item.result, null, 2)}</pre>}
              <div className="card-actions">
                <span>{formatTime(item.createdAt)}</span>
                {item.alertID && (
                  <button className="ghost-button" onClick={() => void onOpenAlert(item.alertID!)} type="button">
                    Open alert
                  </button>
                )}
              </div>
            </article>
          ))}
          {items.length === 0 && <p className="empty">No matching evidence.</p>}
        </div>
      </section>
    </>
  );
}

function AgentsRegistry({ agents, totalCount }: { agents: AgentSummary[]; totalCount: number }) {
  return (
    <>
      <section className="metric-row">
        <Metric label="Agents" value={totalCount} />
        <Metric label="Visible" value={agents.length} />
        <Metric label="Ready" value={agents.filter((agent) => agent.status === 'ok').length} />
        <Metric label="Evidence linked" value={agents.reduce((sum, agent) => sum + agent.evidenceCount, 0)} />
      </section>

      <section className="panel view-panel">
        <PanelHeader title="Agents" count={agents.length} />
        <div className="agent-registry">
          {agents.map((agent) => (
            <article className="agent-card" key={agent.id}>
              <div className="agent-card-head">
                <div className="section-title compact-title">
                  {agentIcon(agent.agent)}
                  <span>{agent.name}</span>
                  {agent.mock && <span className="sample-pill">Mock</span>}
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
          {agents.length === 0 && <p className="empty">No matching agents.</p>}
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

function UnifiedWorkspace({
  detail,
  onClose,
  onRefresh,
  onAnalyze,
  onResolve,
}: {
  detail: DetailState;
  onClose: () => void;
  onRefresh: () => void;
  onAnalyze: (id: string) => Promise<void>;
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
  const similarIncidents = incident?.similar_incidents ?? alert?.similar_incidents ?? [];
  const feedback = incident?.feedback ?? alert?.feedback;
  const targetType = detail.kind;

  return (
    <section className="workspace">
      <div className="workspace-header">
        <div>
          <p className="eyebrow">{detail.kind} detail</p>
          <h2>{title}</h2>
          <div className="meta-line">
            <span>{id}</span>
            <span>{targetLine(labels)}</span>
            <Severity value={detail.data.severity} />
            <Status value={detail.data.status} analyzing={detail.data.is_analyzing} />
          </div>
        </div>
        <div className="workspace-actions">
          <button className="ghost-button" onClick={onClose}><ArrowLeft size={16} /> Back</button>
          <button className="ghost-button" onClick={onRefresh}><RefreshCw size={16} /> Refresh</button>
          {incident && (
            <>
              <button className="ghost-button" onClick={() => onAnalyze(incident.incident_id)}><Bot size={16} /> Analyze</button>
              <button className="primary-button" onClick={() => onResolve(incident.incident_id)}><CheckCircle2 size={16} /> Resolve</button>
            </>
          )}
        </div>
      </div>

      <div className="workspace-body">
        <section className="rca-summary">
          <h3>RCA Summary</h3>
          <p>{summary || 'Analysis is pending. The Agent Evidence Trail will populate as collectors finish.'}</p>
        </section>

        <SimilarIncidentsPanel items={similarIncidents} />

        <section className="rca-report">
          <div className="section-title"><FileText size={18} /> Report</div>
          {analysis ? (
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{analysis}</ReactMarkdown>
          ) : (
            <p className="empty">No RCA report yet.</p>
          )}
        </section>

        <section className="agent-trail">
          <div className="section-title"><Bot size={18} /> Agent Evidence Trail</div>
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

function SimilarIncidentsPanel({ items }: { items: SimilarIncident[] }) {
  return (
    <section className="similar-panel">
      <div className="section-title"><Search size={18} /> Similar Incidents</div>
      {items.length === 0 ? (
        <p className="empty">No similar incident memory yet.</p>
      ) : (
        <div className="similar-list">
          {items.map((item) => (
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
  onSubmitted: () => void;
}) {
  const [selectedVote, setSelectedVote] = useState<'up' | 'down' | null>(null);
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
  const summary = feedback ?? {
    target_type: targetType,
    target_id: targetID,
    positive: 0,
    negative: 0,
    comments: [],
  };

  useEffect(() => {
    setSelectedVote(feedback?.my_vote ?? null);
  }, [targetType, targetID, feedback?.my_vote]);

  useEffect(() => {
    draftEditor.reset('');
    editingEditor.reset('');
    setEditingCommentID('');
    setCommentMenuID('');
    setTab('write');
    setEditingTab('write');
  }, [targetType, targetID]);

  const sendVote = async (vote: 'up' | 'down') => {
    setBusy(true);
    try {
      const nextVote = selectedVote === vote ? 'none' : vote;
      const updated = await submitFeedback(targetType, targetID, nextVote);
      setSelectedVote(updated.my_vote ?? null);
      onSubmitted();
    } finally {
      setBusy(false);
    }
  };

  const sendComment = async () => {
    if (!comment.trim()) return;
    setBusy(true);
    try {
      await addComment(targetType, targetID, comment);
      draftEditor.reset('');
      setTab('write');
      onSubmitted();
    } finally {
      setBusy(false);
    }
  };

  const saveEdit = async () => {
    if (!editingCommentID || !editBody.trim()) return;
    setBusy(true);
    try {
      await updateComment(targetType, targetID, editingCommentID, editBody);
      setEditingCommentID('');
      editingEditor.reset('');
      setEditingTab('write');
      onSubmitted();
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
    try {
      await deleteComment(targetType, targetID, commentID);
      if (editingCommentID === commentID) {
        setEditingCommentID('');
        editingEditor.reset('');
      }
      onSubmitted();
    } finally {
      setCommentActionID('');
      setCommentMenuID('');
    }
  };

  return (
    <section className="feedback-panel">
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
  const [open, setOpen] = useState(agent === 'runai' || agent === 'postgres');
  const icon = agentIcon(agent);
  return (
    <article className="agent-evidence">
      <button className="agent-toggle" onClick={() => setOpen((value) => !value)}>
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
              <div className="artifact" key={`${artifact.agent}-${artifact.type}-${index}`}>
                <div className="artifact-head">
                  <strong>{artifact.type}</strong>
                  <span>{artifact.confidence}</span>
                </div>
                <p>{artifact.summary}</p>
                {artifact.query && <code>{artifact.query}</code>}
                {artifact.result !== undefined && (
                  <pre>{JSON.stringify(artifact.result, null, 2)}</pre>
                )}
              </div>
            ))
          )}
        </div>
      )}
    </article>
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
}: {
  detail: DetailState;
  activeView: MainView;
  incidents: Incident[];
  alerts: AlertRecord[];
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
      setMessages((previous) => [...previous, makeChatMessage('assistant', response.answer)]);
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

function buildAnalysisRecords(alerts: AlertRecord[]): AnalysisRecord[] {
  return alerts
    .map((alert) => {
      const hasAnalysis = Boolean(alert.analysis_summary || alert.analysis_detail);
      const analysisStatus = alert.is_analyzing ? 'analyzing' : hasAnalysis ? 'complete' : 'pending';
      return {
        id: `analysis-${alert.alert_id}`,
        incidentID: alert.incident_id,
        alertID: alert.alert_id,
        title: alert.alarm_title || alert.labels.alertname || alert.alert_id,
        target: targetLine(alert.labels),
        severity: alert.severity,
        alertStatus: alert.status,
        analysisStatus,
        quality: alert.analysis_quality || (hasAnalysis ? 'medium' : 'pending'),
        summary: alert.analysis_summary,
        detail: alert.analysis_detail,
        capabilities: alert.capabilities || {},
        missingData: alert.missing_data || [],
        warnings: alert.warnings || [],
        artifactCount: alert.artifacts?.length || 0,
        similarCount: alert.similar_incidents?.length || 0,
        positiveFeedback: alert.feedback?.positive || 0,
        negativeFeedback: alert.feedback?.negative || 0,
        commentCount: alert.feedback?.comments?.length || 0,
        createdAt: alert.fired_at,
        isAnalyzing: alert.is_analyzing,
        mock: alert.alert_id === MOCK_ALERT.alert_id,
      };
    })
    .sort((left, right) => {
      const statusWeight: Record<string, number> = { analyzing: 0, pending: 1, complete: 2 };
      const delta = (statusWeight[left.analysisStatus] ?? 3) - (statusWeight[right.analysisStatus] ?? 3);
      if (delta !== 0) return delta;
      return right.createdAt.localeCompare(left.createdAt);
    });
}

function buildAnalysisAnalytics(
  records: AnalysisRecord[],
  incidents: Incident[],
  alerts: AlertRecord[],
  windowDays: number,
): AnalysisAnalytics {
  const anchorDate = startOfUtcDay(new Date());
  const windowedIncidents = incidents.filter((incident) => isWithinWindow(incident.fired_at, windowDays, anchorDate));
  const windowedAlerts = alerts.filter((alert) => isWithinWindow(alert.fired_at, windowDays, anchorDate));
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
  const points = Array.from({ length: windowDays }).map((_, index) => {
    const date = addUtcDays(anchorDate, index - windowDays + 1);
    return {
      date: dateKey(date),
      incidents: 0,
      alerts: 0,
    };
  });
  const byDate = new Map(points.map((point) => [point.date, point]));
  incidents.forEach((incident) => {
    const point = byDate.get(dateKey(parseDate(incident.fired_at) ?? anchorDate));
    if (point) point.incidents += 1;
  });
  alerts.forEach((alert) => {
    const point = byDate.get(dateKey(parseDate(alert.fired_at) ?? anchorDate));
    if (point) point.alerts += 1;
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

function mergeCapabilities(items: Record<string, string>[]) {
  const merged: Record<string, string> = {};
  COMPONENT_AGENT_ORDER.forEach((agent) => {
    const statuses = items.map((item) => item[agent]).filter(Boolean);
    if (statuses.includes('ok')) merged[agent] = 'ok';
    else if (statuses.includes('partial')) merged[agent] = 'partial';
    else if (statuses.includes('unavailable')) merged[agent] = 'unavailable';
    else if (statuses.includes('pending')) merged[agent] = 'pending';
  });
  return merged;
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
  const statuses = records.map((record) => record.capabilities[agent]).filter(Boolean);
  if (statuses.includes('ok')) return 'ok';
  if (statuses.includes('partial')) return 'partial';
  if (statuses.includes('unavailable')) return 'unavailable';
  if (statuses.includes('pending')) return 'pending';
  return records.length > 0 ? 'pending' : 'pending';
}

function Severity({ value }: { value: string }) {
  return <span className={`severity severity-${value || 'warning'}`}>{value || 'warning'}</span>;
}

function Status({ value, analyzing = false }: { value: string; analyzing?: boolean }) {
  return <span className={`status status-${value || 'pending'}`}>{analyzing ? 'analyzing' : value}</span>;
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
