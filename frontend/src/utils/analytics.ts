import {
  type AnalysisAnalytics,
  type AnalysisRecord,
  type DistributionItem,
  type RecurringIncidentRow,
  type TrendPoint,
} from '../models/appTypes';
import { AlertRecord, AnalysisRun, Incident } from '../types';
import {
  addUtcDays,
  alertOccurrenceCount,
  average,
  dateKey,
  durationMinutes,
  isActiveWithinWindow,
  isCollectorAgent,
  isWithinWindow,
  normalizeAnalysisSource,
  projectNameFromLabels,
  sourceLabel,
  startOfUtcDay,
  sumAlertOccurrences,
  targetLine,
} from './formatters';

export function buildAnalysisRecords(analysisRuns: AnalysisRun[] = []): AnalysisRecord[] {
  // Analysis lives on runs now (not per-alert columns), so records come from runs.
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
  return runRecords
    .sort((left, right) => {
      const statusWeight: Record<string, number> = { analyzing: 0, pending: 1, failed: 2, complete: 3 };
      const delta = (statusWeight[left.analysisStatus] ?? 4) - (statusWeight[right.analysisStatus] ?? 4);
      if (delta !== 0) return delta;
      return right.createdAt.localeCompare(left.createdAt);
    });
}

export function buildAnalysisAnalytics(
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
  const totalAlerts = sumAlertOccurrences(windowedAlerts);
  const totalIncidents = windowedIncidents.length;

  return {
    anchorDate,
    summary: {
      totalIncidents,
      firingIncidents: windowedIncidents.filter((incident) => incident.status !== 'resolved').length,
      resolvedIncidents: windowedIncidents.filter((incident) => incident.status === 'resolved').length,
      totalAlerts,
      firingAlerts: sumAlertOccurrences(windowedAlerts.filter((alert) => alert.status !== 'resolved')),
      resolvedAlerts: sumAlertOccurrences(windowedAlerts.filter((alert) => alert.status === 'resolved')),
      avgMttrMinutes: average(resolvedDurations),
      avgAlertsPerIncident: totalIncidents === 0 ? 0 : totalAlerts / totalIncidents,
      needsEvidence: windowedRecords.filter((record) => record.missingData.length > 0 || record.warnings.length > 0).length,
    },
    series: buildDailySeries(windowedIncidents, windowedAlerts, windowDays, anchorDate),
    breakdown: {
      incidentSeverity: countBy(windowedIncidents, (incident) => incident.severity || 'unknown'),
      alertSeverity: countAlertOccurrencesBy(windowedAlerts, (alert) => alert.severity || 'unknown'),
      analysisQuality: countBy(windowedRecords, (record) => record.quality || 'pending'),
      topNamespaces: countAlertOccurrencesBy(windowedAlerts, (alert) => alert.labels.namespace || 'unknown').slice(0, 5),
      topQueues: countAlertOccurrencesBy(windowedAlerts, (alert) => alert.labels.queue || alert.labels.runai_queue || 'unknown').slice(0, 5),
      topProjects: countAlertOccurrencesBy(windowedAlerts, (alert) => projectNameFromLabels(alert.labels) || 'unknown').slice(0, 5),
    },
  };
}

export function buildRecurringIncidentRows(
  incidents: Incident[],
  alerts: AlertRecord[],
  windowDays: number,
  anchorDate: Date,
): RecurringIncidentRow[] {
  const incidentsByID = new Map(incidents.map((incident) => [incident.incident_id, incident]));
  const grouped = new Map<string, { id: string; title: string; occurrences: number; alerts: number; similar: number; latest: string }>();
  for (const alert of alerts) {
    if (!isActiveWithinWindow(alert.fired_at, alert.resolved_at ?? '', alert.status, windowDays, anchorDate)) continue;
    const incident = incidentsByID.get(alert.incident_id);
    const id = alert.incident_id || alert.alert_id;
    const row = grouped.get(id) ?? {
      id,
      title: incident?.title || alert.alarm_title,
      occurrences: 0,
      alerts: 0,
      similar: 0,
      latest: alert.fired_at,
    };
    row.occurrences += alertOccurrenceCount(alert);
    row.alerts++;
    row.similar += alert.similar_incidents?.length || 0;
    if (alert.fired_at > row.latest) row.latest = alert.fired_at;
    grouped.set(id, row);
  }
  return [...grouped.values()]
    .map((row) => {
      const recurrenceCount = Math.max(0, row.occurrences - row.alerts);
      const increase = Math.max(recurrenceCount, row.similar);
      return {
        id: row.id,
        title: row.title,
        meta: `${increase} recurrence${increase === 1 ? '' : 's'}`,
        score: row.occurrences + row.similar,
        delta: increase,
      };
    })
    .filter((row) => row.delta > 0)
    .sort((a, b) => b.delta - a.delta || b.score - a.score || a.title.localeCompare(b.title))
    .slice(0, 5);
}

function buildDailySeries(
  incidents: Incident[],
  alerts: AlertRecord[],
  windowDays: number,
  anchorDate: Date,
): TrendPoint[] {
  const days = Array.from({ length: windowDays }).map((_, index) => {
    const date = addUtcDays(anchorDate, index - windowDays + 1);
    const dayStart = startOfUtcDay(date);
    const dayEnd = addUtcDays(dayStart, 1);
    return { date: dateKey(date), dayStart, dayEnd };
  });

  const points: TrendPoint[] = days.map(({ date }) => ({ date, incidents: 0, alerts: 0 }));

  incidents.forEach((incident) => {
    const started = new Date(incident.fired_at);
    if (Number.isNaN(started.getTime())) return;
    const ended = activeEndDate(incident.fired_at, incident.resolved_at ?? '', incident.status);
    days.forEach(({ dayStart, dayEnd }, i) => {
      if (started < dayEnd && (!ended || ended >= dayStart)) {
        points[i].incidents += 1;
      }
    });
  });

  alerts.forEach((alert) => {
    const started = new Date(alert.fired_at);
    if (Number.isNaN(started.getTime())) return;
    const ended = activeEndDate(alert.fired_at, alert.resolved_at ?? '', alert.status);
    days.forEach(({ dayStart, dayEnd }, i) => {
      if (started < dayEnd && (!ended || ended >= dayStart)) {
        points[i].alerts += alertOccurrenceCount(alert);
      }
    });
  });

  return points;
}

function activeEndDate(startedAt: string, resolvedAt: string, status: string) {
  const resolved = new Date(resolvedAt);
  if (!Number.isNaN(resolved.getTime())) return resolved;
  if (status === 'resolved') {
    const started = new Date(startedAt);
    return Number.isNaN(started.getTime()) ? null : started;
  }
  return null;
}

function countBy<T>(items: T[], getKey: (item: T) => string): DistributionItem[] {
  const counts = new Map<string, number>();
  items.forEach((item) => {
    const key = getKey(item) || 'unknown';
    counts.set(key, (counts.get(key) ?? 0) + 1);
  });
  return sortCounts(counts);
}

export function countAlertOccurrencesBy(alerts: AlertRecord[], getKey: (alert: AlertRecord) => string): DistributionItem[] {
  const counts = new Map<string, number>();
  alerts.forEach((alert) => {
    const key = getKey(alert) || 'unknown';
    counts.set(key, (counts.get(key) ?? 0) + alertOccurrenceCount(alert));
  });
  return sortCounts(counts);
}

function sortCounts(counts: Map<string, number>): DistributionItem[] {
  return [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((left, right) => {
      if (right.count !== left.count) return right.count - left.count;
      return left.key.localeCompare(right.key);
    });
}
