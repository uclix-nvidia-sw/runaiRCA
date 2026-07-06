import { AlertRecord, IncidentDetail } from '../types';

export type DetailState =
  | { kind: 'incident'; data: IncidentDetail }
  | { kind: 'alert'; data: AlertRecord }
  | null;

export type EditorTab = 'write' | 'preview';
export type MainView = 'incidents' | 'archived' | 'trash' | 'alerts' | 'analysis';
export type DetailKind = 'incident' | 'alert';
export type IncidentStatusFilter = 'all' | 'firing' | 'resolved' | 'analyzing';
export type IncidentSeverityFilter = 'all' | 'critical' | 'warning' | 'info';
export type IncidentDecisionFilter = 'all' | 'approved' | 'pending';
export type AlertStatusFilter = 'all' | 'firing' | 'resolved' | 'analyzing';

export type IncidentFilterState = {
  status: IncidentStatusFilter;
  severity: IncidentSeverityFilter;
  finalDecision: IncidentDecisionFilter;
};

export type AlertFilterState = {
  status: AlertStatusFilter;
  severity: IncidentSeverityFilter;
};

export type RouteState = {
  view: MainView;
  detailKind?: DetailKind;
  detailID?: string;
};

export type EvidenceItem = {
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

export type AgentSummary = {
  id: string;
  agent: string;
  name: string;
  status: string;
  summary: string;
  source: string;
  lastRun: string;
  evidenceCount: number;
};

export type SynthesisSummary = {
  id: string;
  name: string;
  status: string;
  summary: string;
  source: string;
  lastRun: string;
  runCount: number;
};

export type AnalysisRecord = {
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

export type TrendPoint = {
  date: string;
  incidents: number;
  alerts: number;
};

export type DistributionItem = {
  key: string;
  count: number;
};

export type AnalysisAnalytics = {
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

export type RecurringIncidentRow = {
  id: string;
  title: string;
  meta: string;
  score: number;
  delta: number;
};

export type QueryDisplayItem = {
  id: string;
  name: string;
  queryText: string;
  queryLabel: string;
  status: string;
  statusCode?: number;
  error?: string;
  facts: string[];
  preview?: unknown;
};

export const ANALYSIS_AGENT_ID = 'analysis';
export const COMPONENT_AGENT_ORDER = ['runai', 'kubernetes', 'postgres', 'prometheus', 'loki', 'system'];
export const AGENT_ORDER = COMPONENT_AGENT_ORDER;
export const ANALYSIS_WINDOWS = [
  { label: '7d', days: 7 },
  { label: '14d', days: 14 },
  { label: '30d', days: 30 },
];

export const DEFAULT_INCIDENT_FILTERS: IncidentFilterState = {
  status: 'all',
  severity: 'all',
  finalDecision: 'all',
};

export const DEFAULT_ALERT_FILTERS: AlertFilterState = {
  status: 'all',
  severity: 'all',
};

export const INCIDENT_STATUS_OPTIONS: Array<{ label: string; value: IncidentStatusFilter }> = [
  { label: 'All statuses', value: 'all' },
  { label: 'Firing', value: 'firing' },
  { label: 'Resolved', value: 'resolved' },
  { label: 'Analyzing', value: 'analyzing' },
];

export const INCIDENT_SEVERITY_OPTIONS: Array<{ label: string; value: IncidentSeverityFilter }> = [
  { label: 'All severities', value: 'all' },
  { label: 'Critical', value: 'critical' },
  { label: 'Warning', value: 'warning' },
  { label: 'Info', value: 'info' },
];

export const INCIDENT_DECISION_OPTIONS: Array<{ label: string; value: IncidentDecisionFilter }> = [
  { label: 'All decisions', value: 'all' },
  { label: 'Approved', value: 'approved' },
  { label: 'Pending', value: 'pending' },
];

export const ALERT_STATUS_OPTIONS: Array<{ label: string; value: AlertStatusFilter }> = [
  { label: 'All statuses', value: 'all' },
  { label: 'Firing', value: 'firing' },
  { label: 'Resolved', value: 'resolved' },
  { label: 'Analyzing', value: 'analyzing' },
];

export const VIEW_COPY: Record<MainView, { eyebrow: string; title: string; placeholder: string }> = {
  incidents: {
    eyebrow: 'Incident cockpit',
    title: 'Incident',
    placeholder: 'Search incident, severity, status',
  },
  archived: {
    eyebrow: 'Incident archive',
    title: 'Archived incidents',
    placeholder: 'Search archived incident, severity, status',
  },
  trash: {
    eyebrow: 'Incident trash',
    title: 'Trash',
    placeholder: 'Search deleted incident, severity, status',
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
};
