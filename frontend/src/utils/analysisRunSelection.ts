import { type DetailState } from '../models/appTypes';
import { type AnalysisRun } from '../types';

export function selectedAnalysisRunID(detail: DetailState) {
  if (!detail || detail.kind !== 'incident') return undefined;
  return detail.data.active_analysis_run_id || detail.data.analysis_run_id;
}

function analysisRunMatchesDetail(run: AnalysisRun, detail: DetailState) {
  if (!detail) return false;
  if (detail.kind === 'incident') {
    const incidentID = detail.data.incident_id;
    const alertIDs = new Set(detail.data.alerts.map((alert) => alert.alert_id));
    return (
      run.incident_id === incidentID ||
      (run.target_type === 'incident' && run.target_id === incidentID) ||
      (run.alert_id ? alertIDs.has(run.alert_id) : false) ||
      (run.target_type === 'alert' && alertIDs.has(run.target_id))
    );
  }
  const alertID = detail.data.alert_id;
  return (
    run.alert_id === alertID ||
    (run.target_type === 'alert' && run.target_id === alertID) ||
    run.incident_id === detail.data.incident_id ||
    (run.target_type === 'incident' && run.target_id === detail.data.incident_id)
  );
}

export function analysisRunForDetail(
  detail: DetailState,
  runs: AnalysisRun[],
  exactRun?: AnalysisRun,
) {
  const selectedRunID = selectedAnalysisRunID(detail);
  if (selectedRunID) {
    if (exactRun?.run_id === selectedRunID) return exactRun;
    const selected = runs.find((run) => run.run_id === selectedRunID);
    if (selected) return selected;
    // The incident endpoint selected an authoritative run. When that run is
    // outside the current analysis page, wait for the exact fetch instead of
    // substituting another run that merely belongs to the same incident.
    return undefined;
  }
  return [...runs]
    .filter((run) => analysisRunMatchesDetail(run, detail))
    .sort((left, right) => right.updated_at.localeCompare(left.updated_at))[0];
}
