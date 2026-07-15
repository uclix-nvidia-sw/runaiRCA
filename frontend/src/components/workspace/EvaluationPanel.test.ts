import { describe, expect, it, vi } from 'vitest';

import { EvaluationReview, EvaluationView } from '../../types';

vi.mock('../../api', () => ({
  fetchAnalysisEvaluation: vi.fn(),
  fetchRootCauseFamilies: vi.fn(),
  saveAnalysisEvaluation: vi.fn(),
}));

import {
  evaluationPanelCanSave,
  evaluationPanelReducer,
  initialEvaluationPanelState,
} from './EvaluationPanel';

const review: EvaluationReview = {
  review_id: 'REV-1',
  run_id: 'ANL-1',
  analysis_hash: 'hash-1',
  reviewer: 'operator@example.com',
  case_type: 'known',
  expected_family: 'runai_scheduling_quota',
  scores: {
    evidence_grounding: 5,
    diagnostic_reasoning: 4,
  },
  hard_gates: {},
  resolution_outcome: 'resolved',
  effective_action: 'Raise the project GPU quota.',
  notes: 'Confirmed against scheduler events.',
  created_at: '2026-07-14T00:00:00Z',
  updated_at: '2026-07-14T00:00:00Z',
};

const view: EvaluationView = {
  run_id: 'ANL-1',
  analysis_hash: 'hash-1',
  my_review: review,
  reviews: [review],
  average_score: 4.5,
};

describe('EvaluationPanel loading', () => {
  it('preserves a loaded review and allows saving when the family catalog returns 503', () => {
    let state = evaluationPanelReducer(initialEvaluationPanelState(), {
      type: 'reset',
      runID: 'ANL-1',
      analysisHash: 'hash-1',
    });

    state = evaluationPanelReducer(state, { type: 'evaluation_loaded', view });
    state = evaluationPanelReducer(state, {
      type: 'catalog_failed',
      message: 'Root-cause family catalog unavailable: HTTP 503',
    });

    expect(state.evaluationStatus).toBe('ready');
    expect(state.catalogStatus).toBe('failed');
    expect(state.catalogError).toContain('HTTP 503');
    expect(state.view?.my_review).toEqual(review);
    expect(state.caseType).toBe('known');
    expect(state.expectedFamily).toBe('runai_scheduling_quota');
    expect(state.scores.evidence_grounding).toBe(5);
    expect(state.outcome).toBe('resolved');
    expect(state.effectiveAction).toBe('Raise the project GPU quota.');
    expect(state.notes).toBe('Confirmed against scheduler events.');
    expect(evaluationPanelCanSave(state, 'ANL-1', 'hash-1')).toBe(true);
  });

  it('does not allow saving before the requested evaluation loads', () => {
    let state = evaluationPanelReducer(initialEvaluationPanelState(), {
      type: 'reset',
      runID: 'ANL-2',
      analysisHash: 'hash-2',
    });

    expect(evaluationPanelCanSave(state, 'ANL-2', 'hash-2')).toBe(false);

    state = evaluationPanelReducer(state, {
      type: 'catalog_loaded',
      families: ['runai_scheduling_quota'],
    });

    expect(evaluationPanelCanSave(state, 'ANL-2', 'hash-2')).toBe(false);
  });
});
