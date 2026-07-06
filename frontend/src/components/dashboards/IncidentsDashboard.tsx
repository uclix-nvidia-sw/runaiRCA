import { Archive, MoreHorizontal, RotateCcw, Trash2 } from 'lucide-react';
import { type MouseEvent } from 'react';

import { type IncidentView } from '../../api';
import {
  INCIDENT_DECISION_OPTIONS,
  INCIDENT_SEVERITY_OPTIONS,
  INCIDENT_STATUS_OPTIONS,
  type IncidentFilterState,
} from '../../models/appTypes';
import { Incident, PageInfo } from '../../types';
import {
  FinalDecision,
  Severity,
  Status,
  formatTime,
  trashDaysRemaining,
} from '../../utils/formatters';
import { ColumnFilter, Metric, PaginationControls } from '../common/UiParts';

export function IncidentsDashboard({
  view,
  incidents,
  filteredIncidents,
  filters,
  page,
  loading,
  onOpenIncident,
  onPageChange,
  onFilterChange,
  onArchive,
  onUnarchive,
  onRestore,
  onDelete,
}: {
  view: IncidentView;
  incidents: Incident[];
  filteredIncidents: Incident[];
  filters: IncidentFilterState;
  page: PageInfo;
  loading: boolean;
  onOpenIncident: (id: string) => Promise<void>;
  onPageChange: (page: number) => void;
  onFilterChange: (filters: IncidentFilterState) => void;
  onArchive: (id: string) => Promise<void>;
  onUnarchive: (id: string) => Promise<void>;
  onRestore: (id: string) => Promise<void>;
  onDelete: (id: string, permanent?: boolean) => Promise<void>;
}) {
  let openCount = 0;
  let resolvedCount = 0;
  let analyzingIncidentCount = 0;
  for (const i of incidents) {
    if (i.status === 'resolved') resolvedCount++;
    else openCount++;
    if (i.is_analyzing) analyzingIncidentCount++;
  }
  const updateFilter = <K extends keyof IncidentFilterState>(key: K, value: IncidentFilterState[K]) => {
    onFilterChange({ ...filters, [key]: value });
  };

  return (
    <>
      <section className="metric-row">
        <Metric label="Open incidents" value={openCount} />
        <Metric label="Total incidents" value={page.total} />
        <Metric label="Analyzing" value={analyzingIncidentCount} />
        <Metric label="Resolved incidents" value={resolvedCount} />
      </section>

      <section className="content-grid single-dashboard-grid">
        <div className="panel full-width-panel">
          <table className="operations-table incidents-table">
            <thead>
              <tr>
                <th>Incident</th>
                <th>
                  <ColumnFilter
                    label="Severity"
                    value={filters.severity}
                    options={INCIDENT_SEVERITY_OPTIONS}
                    onChange={(value) => updateFilter('severity', value)}
                  />
                </th>
                <th>
                  <ColumnFilter
                    label="Status"
                    value={filters.status}
                    options={INCIDENT_STATUS_OPTIONS}
                    onChange={(value) => updateFilter('status', value)}
                  />
                </th>
                <th>
                  <ColumnFilter
                    label="Final decision"
                    value={filters.finalDecision}
                    options={INCIDENT_DECISION_OPTIONS}
                    onChange={(value) => updateFilter('finalDecision', value)}
                  />
                </th>
                <th>Alerts</th>
                <th>Started</th>
                <th>Actions</th>
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
                  <td><FinalDecision approvedAt={incident.user_approved_at} /></td>
                  <td>{incident.alert_count}</td>
                  <td>{formatTime(incident.fired_at)}</td>
                  <td>
                    <IncidentRowActions
                      incident={incident}
                      view={view}
                      onArchive={onArchive}
                      onUnarchive={onUnarchive}
                      onRestore={onRestore}
                      onDelete={onDelete}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {loading && <p className="empty">Loading incidents...</p>}
          {!loading && filteredIncidents.length === 0 && <p className="empty">No incidents match the current search.</p>}
          <PaginationControls page={page} disabled={loading} onPageChange={onPageChange} />
        </div>
      </section>
    </>
  );
}

function IncidentRowActions({
  incident,
  view,
  onArchive,
  onUnarchive,
  onRestore,
  onDelete,
}: {
  incident: Incident;
  view: IncidentView;
  onArchive: (id: string) => Promise<void>;
  onUnarchive: (id: string) => Promise<void>;
  onRestore: (id: string) => Promise<void>;
  onDelete: (id: string, permanent?: boolean) => Promise<void>;
}) {
  const run = (event: MouseEvent, work: () => Promise<void>) => {
    event.preventDefault();
    event.stopPropagation();
    event.currentTarget.closest('details')?.removeAttribute('open');
    void work();
  };
  const menuItems = view === 'archived'
    ? [
        { label: 'Unarchive', icon: <RotateCcw size={14} />, action: () => onUnarchive(incident.incident_id) },
        {
          label: 'Delete',
          icon: <Trash2 size={14} />,
          tone: 'danger' as const,
          action: async () => {
            if (window.confirm('Move this archived incident to trash?')) await onDelete(incident.incident_id);
          },
        },
      ]
    : view === 'trash'
      ? [
          { label: 'Restore', icon: <RotateCcw size={14} />, action: () => onRestore(incident.incident_id) },
          {
            label: 'Forever',
            icon: <Trash2 size={14} />,
            tone: 'danger' as const,
            action: async () => {
              if (window.confirm('Delete this incident forever? This cannot be undone.')) await onDelete(incident.incident_id, true);
            },
          },
        ]
      : [
          { label: 'Archive', icon: <Archive size={14} />, action: () => onArchive(incident.incident_id) },
          {
            label: 'Delete',
            icon: <Trash2 size={14} />,
            tone: 'danger' as const,
            action: async () => {
              if (window.confirm('Move this incident to trash?')) await onDelete(incident.incident_id);
            },
          },
        ];
  return (
    <div className="row-action-wrap" onClick={(event) => event.stopPropagation()}>
      <details className="row-action-menu">
        <summary aria-label="Incident actions">
          <MoreHorizontal size={18} />
        </summary>
        <div className="row-action-popover">
          {menuItems.map((item) => (
            <button
              className={item.tone === 'danger' ? 'is-danger' : ''}
              key={item.label}
              onClick={(event) => run(event, item.action)}
              type="button"
            >
              {item.icon}
              {item.label}
            </button>
          ))}
        </div>
      </details>
      {view === 'trash' && <span className="trash-retention">{trashDaysRemaining(incident.deleted_at)}d left</span>}
    </div>
  );
}
