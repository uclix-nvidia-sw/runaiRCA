import { Suspense, lazy, useEffect, useMemo, useState } from 'react';

import { fetchKPIStats, fetchLLMSpendStats, fetchRecurrenceStats } from '../../api';
import {
  ANALYSIS_AGENT_ID,
  ANALYSIS_WINDOWS,
  COMPONENT_AGENT_ORDER,
  type AgentSummary,
  type AnalysisRecord,
  type DistributionItem,
  type RecurringIncidentRow,
  type SynthesisSummary,
  type TrendPoint,
} from '../../models/appTypes';
import { AlertRecord, Incident, KPIStats, LLMSpendStats, RecurrenceStats } from '../../types';
import { buildAnalysisAnalytics, buildRecurringIncidentRows } from '../../utils/analytics';
import {
  Status,
  agentIcon,
  agentLabel,
  dateRangeLabel,
  dominantCapability,
  formatCompactNumber,
  formatDurationMinutes,
  formatTime,
  formatUSD,
  normalizeAgentStatus,
} from '../../utils/formatters';
import { Metric, PanelHeader } from '../common/UiParts';

const TrendChartCanvas = lazy(() => import('../../TrendChartCanvas'));

export function AnalysisDashboard({
  allRecords,
  agents,
  synthesis,
  incidents,
  alerts,
}: {
  allRecords: AnalysisRecord[];
  agents: AgentSummary[];
  synthesis: SynthesisSummary;
  incidents: Incident[];
  alerts: AlertRecord[];
}) {
  const [windowDays, setWindowDays] = useState(14);
  const [recurrence, setRecurrence] = useState<RecurrenceStats | null>(null);
  const [llmSpend, setLLMSpend] = useState<LLMSpendStats | null>(null);
  const [kpiStats, setKpiStats] = useState<KPIStats | null>(null);
  const analytics = useMemo(
    () => buildAnalysisAnalytics(allRecords, incidents, alerts, windowDays),
    [allRecords, alerts, incidents, windowDays],
  );
  const recurringIncidentRows = useMemo(
    () => buildRecurringIncidentRows(incidents, alerts, windowDays, analytics.anchorDate),
    [alerts, analytics.anchorDate, incidents, windowDays],
  );
  const completed = allRecords.filter((record) => record.analysisStatus === 'complete').length;
  const highQuality = allRecords.filter((record) => record.quality === 'high').length;
  const topQuality = analytics.breakdown.analysisQuality[0];
  const topQueue = analytics.breakdown.topQueues[0];
  const topNamespace = analytics.breakdown.topNamespaces[0];
  const topProject = analytics.breakdown.topProjects[0];
  const totalAnalyses = analytics.breakdown.analysisQuality.reduce((sum, item) => sum + item.count, 0);
  const analysisStatCards = [
    { label: 'Severity warning', value: analytics.breakdown.incidentSeverity.find((item) => item.key === 'warning')?.count ?? 0, total: analytics.summary.totalIncidents, detail: 'incidents' },
    { label: 'Severity critical', value: analytics.breakdown.incidentSeverity.find((item) => item.key === 'critical')?.count ?? 0, total: analytics.summary.totalIncidents, detail: 'incidents' },
    { label: 'Analysis quality', value: topQuality?.count ?? 0, total: totalAnalyses, detail: topQuality?.key || 'no data' },
    { label: 'Top queue', value: topQueue?.count ?? 0, total: analytics.summary.totalAlerts, detail: topQueue?.key || 'no data' },
    { label: 'Top namespace', value: topNamespace?.count ?? 0, total: analytics.summary.totalAlerts, detail: topNamespace?.key || 'no data' },
    { label: 'Top project', value: topProject?.count ?? 0, total: analytics.summary.totalAlerts, detail: topProject?.key || 'no data' },
  ];

  useEffect(() => {
    let cancelled = false;
    fetchRecurrenceStats(windowDays)
      .then((stats) => {
        if (!cancelled) setRecurrence(stats);
      })
      .catch(() => {
        if (!cancelled) setRecurrence(null);
      });
    fetchLLMSpendStats(windowDays)
      .then((stats) => {
        if (!cancelled) setLLMSpend(stats);
      })
      .catch(() => {
        if (!cancelled) setLLMSpend(null);
      });
    fetchKPIStats(windowDays)
      .then((stats) => {
        if (!cancelled) setKpiStats(stats);
      })
      .catch(() => {
        if (!cancelled) setKpiStats(null);
      });
    return () => {
      cancelled = true;
    };
  }, [windowDays]);

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
        <Metric label="Avg RCA" value={formatDurationMinutes(kpiStats?.time_to_rca.avg_minutes ?? 0)} />
        <Metric label="Avg MTTR" value={formatDurationMinutes(kpiStats?.time_to_resolve.avg_minutes ?? analytics.summary.avgMttrMinutes)} />
      </section>

      <section className="analysis-pipeline" aria-label="Collector and synthesis pipeline">
        {COMPONENT_AGENT_ORDER.map((agent) => (
          <PipelineStep
            key={agent}
            agent={agent}
            title={agentLabel(agent)}
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

      <section className="analysis-trend-row">
        <section className="analysis-stat-grid" aria-label="Analysis summary">
          {analysisStatCards.map((card) => (
            <article className="analysis-stat-card" key={card.label}>
              <span>{card.label}</span>
              <strong><b>{card.value}</b><em>/{card.total}</em></strong>
              <small>{card.detail}</small>
            </article>
          ))}
        </section>
        <TrendLineChart points={analytics.series} />
      </section>

      <section className="analysis-focus-grid">
        <AgentStatePanel agents={agents} synthesis={synthesis} />

        <div className="analysis-focus-side">
          <div className="analysis-side-stack">
            <RecurrencePanel rows={recurringIncidentRows} stats={recurrence} />
            <LLMSpendPanel stats={llmSpend} />
          </div>
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
        <Suspense fallback={<div className="trend-chart-loading">Loading chart…</div>}>
          <TrendChartCanvas points={points} maxValue={maxValue} yTicks={yTicks} />
        </Suspense>
      </div>
    </section>
  );
}

function AgentStatePanel({ agents, synthesis }: { agents: AgentSummary[]; synthesis: SynthesisSummary }) {
  const rows = [
    ...agents.map((agent) => ({
      id: agent.id,
      agent: agent.agent,
      name: agent.name,
      status: agent.status,
      lastRun: agent.lastRun,
    })),
    {
      id: synthesis.id,
      agent: ANALYSIS_AGENT_ID,
      name: 'Analysis Agent',
      status: synthesis.status,
      lastRun: synthesis.lastRun,
    },
  ];
  const readyCount = rows.filter((row) => normalizeAgentStatus(row.status) === 'ok').length;

  return (
    <section className="agent-state-panel">
      <div className="panel-header compact-panel-header">
        <h3>Agent state</h3>
        <span>{readyCount}/{rows.length}</span>
      </div>
      <div className="agent-state-list">
        {rows.map((row) => (
          <div className="agent-state-row" key={row.id}>
            <div className="agent-state-name">
              <span className="agent-state-icon" aria-hidden="true">{agentIcon(row.agent)}</span>
              <strong>{row.name}</strong>
            </div>
            <span className={`agent-health agent-health-${agentHealthState(row.status)}`}>{agentHealthState(row.status)}</span>
            <time>{formatTime(row.lastRun)}</time>
          </div>
        ))}
      </div>
    </section>
  );
}

function agentHealthState(value: string) {
  const status = normalizeAgentStatus(value);
  if (status === 'analyzing') return 'analyzing';
  return status === 'ok' || status === 'partial' ? 'normal' : 'abnormal';
}

function RecurrencePanel({ rows, stats }: { rows: RecurringIncidentRow[]; stats: RecurrenceStats | null }) {
  return (
    <section className="recurrence-panel">
      <div className="panel-header compact-panel-header">
        <h3>Recurring incidents</h3>
        <span>{stats ? `${Math.round(stats.rate * 100)}%` : '-'}</span>
      </div>
      <div className="recurrence-leaderboard">
        {rows.map((item) => (
          <div className="recurrence-row" key={item.id}>
            <div>
              <strong>{item.title}</strong>
              <span>{item.meta}</span>
            </div>
            <b>+{item.delta}</b>
            <i className={item.delta > 0 ? 'is-up' : 'is-down'} aria-hidden="true" />
          </div>
        ))}
        {rows.length === 0 && <p className="empty compact-empty">No recurrence data</p>}
      </div>
    </section>
  );
}

function LLMSpendPanel({ stats }: { stats: LLMSpendStats | null }) {
  const models = Object.entries(stats?.by_model ?? {})
    .sort(([, left], [, right]) => (right.cost_usd || right.total_tokens) - (left.cost_usd || left.total_tokens))
    .slice(0, 3);
  return (
    <section className="llm-spend-panel">
      <div className="panel-header compact-panel-header">
        <h3>LLM usage</h3>
        <span>{stats ? formatUSD(stats.cost_usd) : '-'}</span>
      </div>
      <div className="llm-spend-summary">
        <div>
          <span>Tokens</span>
          <strong>{formatCompactNumber(stats?.total_tokens ?? 0)}</strong>
        </div>
        <div>
          <span>Calls</span>
          <strong>{stats?.calls ?? 0}</strong>
        </div>
        <div>
          <span>Failed</span>
          <strong>{stats?.failed_calls ?? 0}</strong>
        </div>
      </div>
      <div className="llm-model-list">
        {models.map(([model, bucket]) => (
          <div className="llm-model-row" key={model}>
            <span>{model}</span>
            <b>{formatCompactNumber(bucket.total_tokens)}</b>
            <em>{formatUSD(bucket.cost_usd)}</em>
          </div>
        ))}
        {models.length === 0 && <p className="empty compact-empty">No LLM usage</p>}
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
        {items.slice(0, 6).map((item) => (
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
      <span className="pipeline-icon" aria-hidden="true">{agentIcon(agent)}</span>
      <div className="pipeline-copy">
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
