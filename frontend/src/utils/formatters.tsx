import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Database,
  FileText,
  LineChart,
  ListChecks,
  Server,
} from 'lucide-react';

import {
  COMPONENT_AGENT_ORDER,
  type AnalysisRecord,
  type EvidenceItem,
} from '../models/appTypes';
import { AlertRecord } from '../types';

export function isCollectorAgent(agent: string) {
  return COMPONENT_AGENT_ORDER.includes(agent);
}

export function alertOccurrenceCount(alert: AlertRecord) {
  const count = Number(alert.occurrence_count);
  if (!Number.isFinite(count) || count < 1) {
    return 1;
  }
  return Math.round(count);
}

export function sumAlertOccurrences(alerts: AlertRecord[]) {
  return alerts.reduce((total, alert) => total + alertOccurrenceCount(alert), 0);
}

export function formatOccurrenceCount(alert: AlertRecord) {
  const count = alertOccurrenceCount(alert);
  return `${count} occurrence${count === 1 ? '' : 's'}`;
}

export function sourceLabel(source: string) {
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

export function normalizeAnalysisSource(source: string) {
  if (['auto', 'manual', 'comment', 'feedback', 'chat'].includes(source)) {
    return source;
  }
  return 'manual';
}

export function analysisSourceClass(source: string) {
  return normalizeAnalysisSource(source);
}

export function latestEvidenceForAgent(items: EvidenceItem[], agent: string) {
  return items
    .filter((item) => item.agent === agent)
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
}

export function latestAgentSignal(records: AnalysisRecord[], evidenceItems: EvidenceItem[], agent: string) {
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

export function latestCapabilitySignal(records: AnalysisRecord[], agent: string) {
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

export function normalizeAgentStatus(value?: string) {
  const status = (value || '').trim().toLowerCase();
  if (!status) return '';
  if (['ok', 'complete', 'completed', 'success', 'ready'].includes(status)) return 'ok';
  if (['failed', 'failure', 'error', 'unavailable', 'down'].includes(status)) return 'unavailable';
  if (['partial', 'degraded', 'warning'].includes(status)) return 'partial';
  if (['running', 'analyzing', 'in_progress'].includes(status)) return 'analyzing';
  if (status === 'pending') return 'pending';
  return status;
}

export function worstAgentStatus(statuses: string[]) {
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

export function uniqueStrings(items: string[]) {
  return [...new Set(items.filter(Boolean))];
}

export function isWithinWindow(value: string, windowDays: number, anchorDate: Date) {
  const parsed = parseDate(value);
  if (!parsed) return false;
  const start = addUtcDays(anchorDate, -windowDays + 1);
  const day = startOfUtcDay(parsed);
  return day >= start && day <= anchorDate;
}

export function isActiveWithinWindow(
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

export function activeEndDate(startedAt: string, resolvedAt: string, status: string) {
  const resolved = parseDate(resolvedAt);
  if (resolved) return resolved;
  if (status === 'resolved') return parseDate(startedAt);
  return null;
}

export function durationMinutes(start: string, end: string) {
  const startDate = parseDate(start);
  const endDate = parseDate(end);
  if (!startDate || !endDate) return 0;
  return Math.max(0, Math.round((endDate.getTime() - startDate.getTime()) / 60000));
}

export function average(values: number[]) {
  if (values.length === 0) return 0;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

export function parseDate(value: string) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

// ponytail: buckets align to Asia/Seoul (KST, fixed UTC+9) calendar days, not UTC.
// KST has no DST, so a constant +9h offset is exact; no Intl zone math needed.
const KST_OFFSET_MS = 9 * 60 * 60 * 1000;

export function startOfUtcDay(date: Date) {
  const shifted = new Date(date.getTime() + KST_OFFSET_MS);
  const kstMidnight = Date.UTC(shifted.getUTCFullYear(), shifted.getUTCMonth(), shifted.getUTCDate());
  return new Date(kstMidnight - KST_OFFSET_MS);
}

export function addUtcDays(date: Date, days: number) {
  return new Date(date.getTime() + days * 24 * 60 * 60 * 1000);
}

export function dateKey(date: Date) {
  return new Date(date.getTime() + KST_OFFSET_MS).toISOString().slice(0, 10);
}

export function dateRangeLabel(points: Array<{ date: string }>) {
  if (points.length === 0) return '-';
  return `${points[0].date} - ${points[points.length - 1].date}`;
}

export function formatDurationMinutes(value: number) {
  if (!value) return '0m';
  if (value < 60) return `${Math.round(value)}m`;
  const hours = value / 60;
  return `${formatDecimal(hours)}h`;
}

export function formatDecimal(value: number) {
  return value.toFixed(1);
}

export function formatCompactNumber(value: number) {
  if (!Number.isFinite(value)) return '0';
  return new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 }).format(value);
}

export function formatUSD(value: number) {
  if (!Number.isFinite(value) || value <= 0) return '$0';
  if (value < 0.01) return `$${value.toFixed(4)}`;
  return `$${value.toFixed(2)}`;
}

export function dominantCapability(records: AnalysisRecord[], agent: string) {
  return latestCapabilitySignal(records, agent)?.status || 'pending';
}

export function Severity({ value }: { value: string }) {
  return <span className={`severity severity-${value || 'warning'}`}>{value || 'warning'}</span>;
}

function statusLabel(value: string) {
  const displayValue = value || 'pending';
  if (displayValue === 'ok' || displayValue === 'partial') return '';
  const labels: Record<string, string> = {
    ready_for_review: 'ready for review',
    validation_failed: 'validation failed',
  };
  return labels[displayValue] || displayValue;
}

export function Status({ value, analyzing = false }: { value: string; analyzing?: boolean }) {
  const displayValue = analyzing ? 'analyzing' : (value || 'pending');
  const label = statusLabel(displayValue);
  if (!label) return null;
  return <span className={`status status-${displayValue}`}>{label}</span>;
}

export function FinalDecision({ approvedAt }: { approvedAt?: string | null }) {
  return <span className={`status ${approvedAt ? 'status-resolved' : 'status-pending'}`}>{approvedAt ? 'approved' : 'pending'}</span>;
}

export function targetLine(labels: Record<string, string>) {
  const project = projectNameFromLabels(labels);
  const namespace = labels.namespace || labels.kubernetes_namespace || '';
  const workload = labels.workload || labels.workload_name || labels.pod || 'workload unknown';
  if (!project && namespace) {
    return `${namespace} / ${workload}`;
  }
  if (!project) {
    return workload;
  }
  return `${project} / ${workload}`;
}

export function projectNameFromLabels(labels: Record<string, string>) {
  const explicit = labels.project || labels.runai_project || labels['runai.io/project'];
  if (explicit) return stripRunaiNamespacePrefix(explicit);
  return projectNameFromNamespace(labels.namespace || labels.kubernetes_namespace || '');
}

// Namespaces that start with "runai-" but are NOT a Run:ai user project — the
// platform and the RCA product's own namespace. Deriving a project off these
// showed a bogus "backend"/"rca" instead of the real namespace (runai-rca).
const NON_PROJECT_NAMESPACES = new Set(['runai', 'runai-backend', 'runai-rca']);

function projectNameFromNamespace(namespace: string) {
  if (NON_PROJECT_NAMESPACES.has(namespace)) return '';
  return namespace.startsWith('runai-') ? namespace.slice('runai-'.length) : '';
}

function stripRunaiNamespacePrefix(value: string) {
  return value.startsWith('runai-') ? value.slice('runai-'.length) : value;
}

const KST_FORMAT = new Intl.DateTimeFormat('sv-SE', {
  timeZone: 'Asia/Seoul',
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  hour12: false,
});

export function formatTime(value: string) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return KST_FORMAT.format(date).replace(',', '');
}

export function trashDaysRemaining(deletedAt?: string | null) {
  if (!deletedAt) return 30;
  const deleted = new Date(deletedAt).getTime();
  if (Number.isNaN(deleted)) return 30;
  const expires = deleted + 30 * 24 * 60 * 60 * 1000;
  return Math.max(0, Math.ceil((expires - Date.now()) / (24 * 60 * 60 * 1000)));
}

export function formatTokenUsage(usage: Record<string, unknown>) {
  const total = numberField(usage.total_tokens);
  const prompt = numberField(usage.prompt_tokens);
  const completion = numberField(usage.completion_tokens);
  const calls = numberField(usage.calls);
  return [
    total !== undefined ? `${total.toLocaleString()} total` : undefined,
    prompt !== undefined ? `${prompt.toLocaleString()} prompt` : undefined,
    completion !== undefined ? `${completion.toLocaleString()} completion` : undefined,
    calls !== undefined ? `${calls} call${calls === 1 ? '' : 's'}` : undefined,
  ].filter(Boolean).join(' · ') || 'recorded';
}

function numberField(value: unknown) {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

export function agentLabel(agent: string) {
  const labels: Record<string, string> = {
    analysis: 'Analysis',
    runai: 'Run:AI',
    kubernetes: 'Kubernetes',
    postgres: 'Postgres',
    prometheus: 'Prometheus',
    loki: 'Loki',
    system: 'System',
  };
  return labels[agent] || agent;
}

export function agentIcon(agent: string) {
  if (agent === 'analysis') return <ListChecks size={18} />;
  if (agent === 'runai') return <Activity size={18} />;
  if (agent === 'kubernetes') return <Server size={18} />;
  if (agent === 'postgres') return <Database size={18} />;
  if (agent === 'prometheus') return <LineChart size={18} />;
  if (agent === 'loki') return <FileText size={18} />;
  if (agent === 'system') return <Cpu size={18} />;
  return <AlertTriangle size={18} />;
}
