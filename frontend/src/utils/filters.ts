import {
  type AlertFilters as AlertQueryFilters,
  type IncidentFilters as IncidentQueryFilters,
  type IncidentView,
} from '../api';
import { AlertFilterState, IncidentFilterState, MainView } from '../models/appTypes';
import { AlertRecord, Incident } from '../types';

export function incidentViewForMainView(view: MainView): IncidentView {
  if (view === 'archived') return 'archived';
  if (view === 'trash') return 'trash';
  return 'active';
}

export function incidentFiltersForAPI(filters: IncidentFilterState): IncidentQueryFilters {
  return {
    status: filters.status === 'all' ? undefined : filters.status,
    severity: filters.severity === 'all' ? undefined : filters.severity,
    finalDecision: filters.finalDecision === 'all' ? undefined : filters.finalDecision,
  };
}

export function alertFiltersForAPI(filters: AlertFilterState): AlertQueryFilters {
  return {
    status: filters.status === 'all' ? undefined : filters.status,
    severity: filters.severity === 'all' ? undefined : filters.severity,
  };
}

export function matchesIncidentFilters(incident: Incident, filters: IncidentFilterState) {
  if (filters.status !== 'all') {
    if (filters.status === 'analyzing') {
      if (!incident.is_analyzing) return false;
    } else if (incident.status !== filters.status) {
      return false;
    }
  }
  if (filters.severity !== 'all' && incident.severity !== filters.severity) return false;
  if (filters.finalDecision === 'approved' && !incident.user_approved_at) return false;
  if (filters.finalDecision === 'pending' && incident.user_approved_at) return false;
  return true;
}

export function matchesAlertFilters(alert: AlertRecord, filters: AlertFilterState) {
  if (filters.status !== 'all') {
    if (filters.status === 'analyzing') {
      if (!alert.is_analyzing) return false;
    } else if (alert.status !== filters.status) {
      return false;
    }
  }
  if (filters.severity !== 'all' && alert.severity !== filters.severity) return false;
  return true;
}
