import {
  Activity,
  AlertTriangle,
  Bot,
  CheckCircle2,
  ChevronDown,
  Database,
  FileText,
  LineChart,
  MessageSquare,
  RefreshCw,
  Search,
  Server,
  X,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {
  analyzeIncident,
  chat,
  eventSource,
  fetchAlert,
  fetchAlerts,
  fetchIncident,
  fetchIncidents,
  resolveIncident,
} from './api';
import { AlertRecord, Artifact, Incident, IncidentDetail } from './types';

type DetailState =
  | { kind: 'incident'; data: IncidentDetail }
  | { kind: 'alert'; data: AlertRecord }
  | null;

const AGENT_ORDER = ['runai', 'kubernetes', 'postgres', 'prometheus', 'loki'];

function App() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [detail, setDetail] = useState<DetailState>(null);
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
    return () => source.close();
  }, [load]);

  const filteredIncidents = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return incidents;
    return incidents.filter((incident) =>
      [incident.title, incident.severity, incident.status, incident.correlation_key]
        .join(' ')
        .toLowerCase()
        .includes(q),
    );
  }, [incidents, query]);

  const filteredAlerts = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return alerts;
    return alerts.filter((alert) =>
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
  }, [alerts, query]);

  const openIncident = async (id: string) => {
    setDetail({ kind: 'incident', data: await fetchIncident(id) });
  };

  const openAlert = async (id: string) => {
    setDetail({ kind: 'alert', data: await fetchAlert(id) });
  };

  const refreshDetail = async () => {
    if (!detail) return;
    if (detail.kind === 'incident') {
      setDetail({ kind: 'incident', data: await fetchIncident(detail.data.incident_id) });
    } else {
      setDetail({ kind: 'alert', data: await fetchAlert(detail.data.alert_id) });
    }
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-mark">N</div>
        <div>
          <p className="eyebrow">NVIDIA Run:ai</p>
          <h1>Run:AI RCA</h1>
        </div>
        <nav>
          <a className="nav-item active"><Activity size={18} /> Operations</a>
          <a className="nav-item"><Database size={18} /> Evidence</a>
          <a className="nav-item"><Bot size={18} /> Agents</a>
        </nav>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <p className="eyebrow">Incident cockpit</p>
            <h2>GPU workload RCA workspace</h2>
          </div>
          <div className="search-box">
            <Search size={17} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search project, queue, workload, status"
            />
          </div>
          <button className="icon-button" onClick={() => void load()} aria-label="Refresh">
            <RefreshCw size={18} />
          </button>
        </header>

        {error && <div className="error-banner">{error}</div>}

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
                  <tr key={incident.incident_id} onClick={() => void openIncident(incident.incident_id)}>
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
                  <tr key={alert.alert_id} onClick={() => void openAlert(alert.alert_id)}>
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
      <FloatingChat detail={detail} />
    </div>
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
          <button className="ghost-button" onClick={onRefresh}><RefreshCw size={16} /> Refresh</button>
          {incident && (
            <>
              <button className="ghost-button" onClick={() => onAnalyze(incident.incident_id)}><Bot size={16} /> Analyze</button>
              <button className="primary-button" onClick={() => onResolve(incident.incident_id)}><CheckCircle2 size={16} /> Resolve</button>
            </>
          )}
          <button className="icon-button" onClick={onClose} aria-label="Close"><X size={17} /></button>
        </div>
      </div>

      <div className="workspace-body">
        <section className="rca-summary">
          <h3>RCA Summary</h3>
          <p>{summary || 'Analysis is pending. The Agent Evidence Trail will populate as collectors finish.'}</p>
        </section>

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

function FloatingChat({ detail }: { detail: DetailState }) {
  const [open, setOpen] = useState(false);
  const [message, setMessage] = useState('');
  const [answer, setAnswer] = useState('');
  const context =
    detail?.kind === 'incident'
      ? { incident_id: detail.data.incident_id }
      : detail?.kind === 'alert'
        ? { alert_id: detail.data.alert_id, incident_id: detail.data.incident_id }
        : {};

  const send = async () => {
    if (!message.trim()) return;
    const response = await chat(message, context);
    setAnswer(response.answer);
    setMessage('');
  };

  return (
    <>
      {open && (
        <section className="chat-panel">
          <header>
            <div><MessageSquare size={17} /> RCA Chat</div>
            <button onClick={() => setOpen(false)} aria-label="Close chat"><X size={17} /></button>
          </header>
          <p>{answer || 'Ask about the current incident, alert, or Run:AI workload.'}</p>
          <textarea value={message} onChange={(event) => setMessage(event.target.value)} />
          <button className="primary-button" onClick={() => void send()}>Send</button>
        </section>
      )}
      <button className="chat-fab" onClick={() => setOpen(true)} aria-label="Open chat">
        <MessageSquare size={22} />
      </button>
    </>
  );
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
    runai: 'Run:AI',
    kubernetes: 'Kubernetes',
    postgres: 'Postgres',
    prometheus: 'Prometheus',
    loki: 'Loki',
  };
  return labels[agent] || agent;
}

function agentIcon(agent: string) {
  if (agent === 'runai') return <Activity size={18} />;
  if (agent === 'kubernetes') return <Server size={18} />;
  if (agent === 'postgres') return <Database size={18} />;
  if (agent === 'prometheus') return <LineChart size={18} />;
  if (agent === 'loki') return <FileText size={18} />;
  return <AlertTriangle size={18} />;
}

export default App;
