import { AnalysisProgressEntry } from '../types';

export type RealtimeEventPayload = {
  type?: string;
  data?: {
    run_id?: string;
    source?: string;
    status?: string;
    target_type?: 'incident' | 'alert';
    target_id?: string;
    incident_id?: string;
    alert_id?: string;
  } & AnalysisProgressEntry;
};

export function parseRealtimeEvent(event: Event): RealtimeEventPayload | undefined {
  if (!(event instanceof MessageEvent) || typeof event.data !== 'string') return undefined;
  try {
    return JSON.parse(event.data) as RealtimeEventPayload;
  } catch {
    return undefined;
  }
}

export function appendProgress(
  current: Record<string, AnalysisProgressEntry[]>,
  payload: RealtimeEventPayload | undefined,
) {
  if (payload?.type !== 'analysis.progress' || !payload.data?.run_id) return current;
  const runID = payload.data.run_id;
  const entry: AnalysisProgressEntry = {
    ...payload.data,
    seq: typeof payload.data.seq === 'number' ? payload.data.seq : Number(payload.data.seq || 0),
  };
  const existing = current[runID] ?? [];
  const withoutDuplicate = entry.seq
    ? existing.filter((item) => item.seq !== entry.seq)
    : existing;
  return {
    ...current,
    [runID]: [...withoutDuplicate, entry].slice(-200),
  };
}
