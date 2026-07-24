import { Archive, CheckSquare, MoreHorizontal, RotateCcw, Trash2, X } from 'lucide-react';
import { type MouseEvent, useEffect, useMemo, useState } from 'react';

import { type BulkIncidentAction, type IncidentView } from '../../api';
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
  onBulkAction,
  onEmptyTrash,
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
  onBulkAction: (ids: string[], action: BulkIncidentAction) => Promise<void>;
  onEmptyTrash: () => Promise<void>;
}) {
  const [selectedIDs, setSelectedIDs] = useState<string[]>([]);
  const [isApplyingBulkAction, setIsApplyingBulkAction] = useState(false);
  const visibleIDs = useMemo(() => filteredIncidents.map((incident) => incident.incident_id), [filteredIncidents]);
  const visibleIDKey = visibleIDs.join('\u0000');
  const selectedIDSet = useMemo(() => new Set(selectedIDs), [selectedIDs]);
  const allVisibleSelected = visibleIDs.length > 0 && visibleIDs.every((id) => selectedIDSet.has(id));

  useEffect(() => {
    const visible = new Set(visibleIDs);
    setSelectedIDs((current) => current.filter((id) => visible.has(id)));
  }, [visibleIDKey]);

  const updateFilter = <K extends keyof IncidentFilterState>(key: K, value: IncidentFilterState[K]) => {
    onFilterChange({ ...filters, [key]: value });
  };
  const toggleSelected = (id: string) => {
    setSelectedIDs((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id]);
  };
  const toggleAllVisible = () => {
    setSelectedIDs(allVisibleSelected ? [] : visibleIDs);
  };
  const runBulkAction = async (action: BulkIncidentAction, confirmation?: string) => {
    if (selectedIDs.length === 0 || (confirmation && !window.confirm(confirmation))) return;
    setIsApplyingBulkAction(true);
    try {
      await onBulkAction(selectedIDs, action);
      setSelectedIDs([]);
    } finally {
      setIsApplyingBulkAction(false);
    }
  };
  const emptyTrash = async () => {
    if (!window.confirm(`Permanently delete all ${page.total} incident${page.total === 1 ? '' : 's'} in trash? This cannot be undone.`)) return;
    setIsApplyingBulkAction(true);
    try {
      await onEmptyTrash();
      setSelectedIDs([]);
    } finally {
      setIsApplyingBulkAction(false);
    }
  };

  return (
    <>
      <section className="metric-row">
        <Metric label="Open incidents" value={page.counts?.open ?? 0} />
        <Metric label="Total incidents" value={page.total} />
        <Metric label="Analyzing" value={page.counts?.analyzing ?? 0} />
        <Metric label="Resolved incidents" value={page.counts?.resolved ?? 0} />
      </section>

      <section className="content-grid single-dashboard-grid">
        <div className="panel full-width-panel">
          <BulkIncidentActions
            view={view}
            count={selectedIDs.length}
            hasTrash={page.total > 0}
            busy={isApplyingBulkAction || loading}
            onClear={() => setSelectedIDs([])}
            onAction={runBulkAction}
            onEmptyTrash={emptyTrash}
          />
          <table className="operations-table incidents-table">
            <thead>
              <tr>
                <th className="selection-column">
                  <input
                    type="checkbox"
                    checked={allVisibleSelected}
                    onChange={toggleAllVisible}
                    disabled={visibleIDs.length === 0 || isApplyingBulkAction}
                    aria-label="Select all visible incidents"
                  />
                </th>
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
                <tr
                  key={incident.incident_id}
                  className={selectedIDSet.has(incident.incident_id) ? 'is-selected' : ''}
                  tabIndex={0}
                  onClick={() => void onOpenIncident(incident.incident_id)}
                  onKeyDown={(event) => {
                    // ponytail: guard skips events bubbling up from the nested action menu
                    if (event.target !== event.currentTarget) return;
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      void onOpenIncident(incident.incident_id);
                    }
                  }}
                >
                  <td className="selection-column" onClick={(event) => event.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={selectedIDSet.has(incident.incident_id)}
                      onChange={() => toggleSelected(incident.incident_id)}
                      disabled={isApplyingBulkAction}
                      aria-label={`Select ${incident.title}`}
                    />
                  </td>
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

function BulkIncidentActions({
  view,
  count,
  hasTrash,
  busy,
  onClear,
  onAction,
  onEmptyTrash,
}: {
  view: IncidentView;
  count: number;
  hasTrash: boolean;
  busy: boolean;
  onClear: () => void;
  onAction: (action: BulkIncidentAction, confirmation?: string) => Promise<void>;
  onEmptyTrash: () => Promise<void>;
}) {
  const primary = view === 'active'
    ? { label: 'Archive selected', icon: <Archive size={15} />, action: 'archive' as const }
    : view === 'archived'
      ? { label: 'Unarchive selected', icon: <RotateCcw size={15} />, action: 'unarchive' as const }
      : { label: 'Restore selected', icon: <RotateCcw size={15} />, action: 'restore' as const };
  const destructiveAction: BulkIncidentAction = view === 'trash' ? 'delete_permanently' : 'trash';

  return (
    <div className="bulk-actions" aria-live="polite">
      {count > 0 ? (
        <>
          <span className="bulk-selection-count"><CheckSquare size={16} />{count} selected</span>
          <button className="ghost-button compact-button" type="button" disabled={busy} onClick={() => void onAction(primary.action)}>
            {primary.icon}{primary.label}
          </button>
          <button
            className="danger-button compact-button"
            type="button"
            disabled={busy}
            onClick={() => void onAction(
              destructiveAction,
              `Are you sure you want to ${view === 'trash' ? 'permanently delete' : 'move to trash'} ${count} selected incident${count === 1 ? '' : 's'}?${view === 'trash' ? ' This cannot be undone.' : ''}`,
            )}
          >
            <Trash2 size={15} />{view === 'trash' ? 'Delete forever' : 'Move to trash'}
          </button>
          <button className="bulk-clear-button" type="button" disabled={busy} onClick={onClear}>
            <X size={15} />Clear
          </button>
        </>
      ) : (
        <span className="bulk-selection-hint">Select incidents to manage them together.</span>
      )}
      {view === 'trash' && hasTrash && (
        <button className="danger-button compact-button bulk-empty-trash" type="button" disabled={busy} onClick={() => void onEmptyTrash()}>
          <Trash2 size={15} />Empty trash
        </button>
      )}
    </div>
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
