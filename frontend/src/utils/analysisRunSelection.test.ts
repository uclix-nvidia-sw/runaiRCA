import { describe, expect, it } from 'vitest';

import { type DetailState } from '../models/appTypes';
import { type AnalysisRun } from '../types';
import { analysisRunForDetail, selectedAnalysisRunID } from './analysisRunSelection';

function run(runID: string, incidentID = 'INC-1'): AnalysisRun {
  return {
    run_id: runID,
    source: 'manual',
    status: 'complete',
    target_type: 'incident',
    target_id: incidentID,
    incident_id: incidentID,
    title: runID,
    analysis_summary: runID,
    analysis_detail: '',
    analysis_quality: 'high',
    capabilities: {},
    missing_data: [],
    warnings: [],
    artifacts: [],
    created_at: '2026-07-14T00:00:00Z',
    updated_at: '2026-07-14T00:00:00Z',
  };
}

function incidentDetail(overrides: Record<string, unknown> = {}): DetailState {
  return {
    kind: 'incident',
    data: {
      incident_id: 'INC-1',
      correlation_key: 'cluster/runai/INC-1',
      title: 'Incident 1',
      severity: 'warning',
      status: 'firing',
      fired_at: '2026-07-14T00:00:00Z',
      alert_count: 0,
      is_analyzing: false,
      analysis_run_id: 'ANL-selected',
      active_analysis_run_id: undefined,
      analysis_summary: '',
      analysis_detail: '',
      analysis_quality: '',
      capabilities: {},
      missing_data: [],
      warnings: [],
      artifacts: [],
      similar_incidents: [],
      similar_recent_count: 0,
      feedback: {
        target_type: 'incident',
        target_id: 'INC-1',
        positive: 0,
        negative: 0,
        comments: [],
      },
      alerts: [],
      ...overrides,
    },
  };
}

describe('analysis run selection', () => {
  it('does not use a broad incident match while the selected run is outside the page', () => {
    const detail = incidentDetail();
    const broadMatch = run('ANL-other');

    expect(analysisRunForDetail(detail, [broadMatch])).toBeUndefined();

    const exact = run('ANL-selected');
    expect(analysisRunForDetail(detail, [broadMatch], exact)).toBe(exact);
  });

  it('prefers the active run id over the last-good RCA id', () => {
    const detail = incidentDetail({ active_analysis_run_id: 'ANL-active' });
    const lastGood = run('ANL-selected');
    const active = { ...run('ANL-active'), status: 'analyzing' };

    expect(selectedAnalysisRunID(detail)).toBe('ANL-active');
    expect(analysisRunForDetail(detail, [lastGood, active])).toBe(active);
  });
});
