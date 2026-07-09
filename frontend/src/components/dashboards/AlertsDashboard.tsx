import { Link } from 'lucide-react';

import {
  ALERT_STATUS_OPTIONS,
  INCIDENT_SEVERITY_OPTIONS,
  type AlertFilterState,
} from '../../models/appTypes';
import { AlertRecord, PageInfo } from '../../types';
import {
  Severity,
  Status,
  formatOccurrenceCount,
  sumAlertOccurrences,
  targetLine,
} from '../../utils/formatters';
import { ColumnFilter, Metric, PaginationControls } from '../common/UiParts';

export function AlertsDashboard({
  alerts,
  filteredAlerts,
  filters,
  page,
  loading,
  onOpenIncident,
  onPageChange,
  onFilterChange,
}: {
  alerts: AlertRecord[];
  filteredAlerts: AlertRecord[];
  filters: AlertFilterState;
  page: PageInfo;
  loading: boolean;
  onOpenIncident: (id: string) => Promise<void>;
  onPageChange: (page: number) => void;
  onFilterChange: (filters: AlertFilterState) => void;
}) {
  const analyzingCount = alerts.filter((alert) => alert.is_analyzing).length;
  const totalOccurrences = sumAlertOccurrences(alerts);
  const firingOccurrences = sumAlertOccurrences(alerts.filter((alert) => alert.status !== 'resolved'));
  const resolvedOccurrences = sumAlertOccurrences(alerts.filter((alert) => alert.status === 'resolved'));
  const updateFilter = <K extends keyof AlertFilterState>(key: K, value: AlertFilterState[K]) => {
    onFilterChange({ ...filters, [key]: value });
  };

  return (
    <>
      <section className="metric-row">
        <Metric label="Firing occurrences" value={firingOccurrences} />
        <Metric label="Alert groups" value={page.total} />
        <Metric label="Analyzing" value={analyzingCount} />
        <Metric label="Resolved occurrences" value={resolvedOccurrences} />
      </section>

      <section className="content-grid single-dashboard-grid">
        <div className="panel full-width-panel">
          <table className="operations-table alerts-table">
            <thead>
              <tr>
                <th>Alert</th>
                <th>Target</th>
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
                    options={ALERT_STATUS_OPTIONS}
                    onChange={(value) => updateFilter('status', value)}
                  />
                </th>
                <th>Incident</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map((alert) => (
                <tr key={alert.alert_id} onClick={() => void onOpenIncident(alert.incident_id)}>
                  <td>
                    <strong>{alert.alarm_title}</strong>
                    <span className="table-subline">
                      {alert.alert_id}
                      <span className="occurrence-pill">{formatOccurrenceCount(alert)}</span>
                    </span>
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
          {!loading && filteredAlerts.length > 0 && totalOccurrences > filteredAlerts.length && (
            <p className="table-note">
              Showing {filteredAlerts.length} alert group(s) covering {sumAlertOccurrences(filteredAlerts)} occurrence(s).
            </p>
          )}
          <PaginationControls page={page} disabled={loading} onPageChange={onPageChange} />
        </div>
      </section>
    </>
  );
}
