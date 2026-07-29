import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { ConfidenceBreakdownPanel, parseConfidenceBreakdown } from './ConfidenceBreakdownPanel';

describe('parseConfidenceBreakdown', () => {
  it('keeps deterministic ranking and harness quality data separate', () => {
    const view = parseConfidenceBreakdown({
      ranking_candidate: {
        family: 'image_pull_error',
        confidence: 'medium',
        score: 9,
        independent_source_groups: ['kubernetes_api', 'registry'],
        score_breakdown: [{
          stage: 'evidence',
          label: 'kubernetes scoped supporting facts',
          delta: 4,
          source_groups: ['kubernetes_api'],
        }, {
          stage: 'prior',
          label: 'feedback prior',
          factor: 1.25,
        }, {
          stage: 'signature',
          label: 'typed runtime signature',
          score_floor: 9,
        }],
        confidence_gate: {
          score_floor: 2,
          score_floor_passed: true,
          required_independent_source_groups: 2,
          independent_source_groups: ['kubernetes_api', 'registry'],
          independent_source_gate_passed: true,
          unresolved_contradiction: false,
        },
      },
      pre_harness_candidate: { family: 'image_pull_error', confidence: 'medium' },
      final_candidate: { family: 'image_pull_error', confidence: 'medium' },
      self_check: {
        confidence_before: 'high',
        confidence_after: 'medium',
        refuted: false,
        caveat: 'Repository existence and authorization remain ambiguous.',
        next_check: 'Run a scoped image pull check.',
      },
      harness: {
        status: 'pass',
        overall_score: 86,
        confidence_before: 'medium',
        confidence_after: 'medium',
        hard_gates: { unsupported_high_confidence: false },
      },
    });

    expect(view?.hasRankingDetails).toBe(true);
    expect(view?.family).toBe('image_pull_error');
    expect(view?.rankingScore).toBe(9);
    expect(view?.rankingConfidence).toBe('medium');
    expect(view?.preHarnessConfidence).toBe('medium');
    expect(view?.independentSourceGroups).toEqual(['kubernetes_api', 'registry']);
    expect(view?.scoreRows).toEqual([
      {
        stage: 'evidence',
        label: 'kubernetes scoped supporting facts',
        effect: '0 → 4 (+4)',
        sourceGroups: ['kubernetes_api'],
        evidenceIds: [],
      },
      { stage: 'prior', label: 'feedback prior', effect: '4 → 5 (×1.25)', sourceGroups: [], evidenceIds: [] },
      { stage: 'signature', label: 'typed runtime signature', effect: '하한 9점 적용 (누적 5점 대체)', sourceGroups: [], evidenceIds: [] },
    ]);
    expect(view?.gateRows.find((row) => row.label === '미해결 반증 없음')?.outcome).toBe('pass');
    expect(view?.selfCheck?.before).toBe('high');
    expect(view?.harness?.overallScore).toBe(86);
    expect(view?.harness?.hardGates[0].outcome).toBe('pass');
  });

  it('formats score floors as replacements even when a legacy row also has delta', () => {
    const view = parseConfidenceBreakdown({
      ranking_candidate: {
        score_breakdown: [
          { stage: 'evidence', label: 'supporting fact', delta: 2 },
          { stage: 'signature', label: 'typed signature', delta: 7, score_floor: 9 },
        ],
      },
    });

    expect(view?.scoreRows[1].effect).toBe('하한 9점 적용 (누적 2점 대체)');
    expect(view?.scoreRows[1].effect).not.toContain('→');
    expect(view?.scoreRows[1].effect).not.toContain('+7');
  });

  it('renders score-row evidence ids and the run score note', () => {
    const diagnostics = {
      ranking_candidate: {
        family: 'workload_runtime_error',
        score: 7,
        score_breakdown: [{
          stage: 'signature',
          label: 'typed OOMKilled state',
          score_floor: 7,
          evidence_ids: ['E12'],
        }],
        confidence_gate: {
          score_floor: 2,
          medium_score_threshold: 2,
          high_score_threshold: 5,
        },
      },
    };
    const markup = renderToStaticMarkup(ConfidenceBreakdownPanel({ diagnostics }));

    expect(markup).toContain('Evidence ID');
    expect(markup).toContain('E12');
    expect(markup).toContain('아래는 7점의 구성요소가 아니라');
    expect(markup).toContain('7점 (상한 없음 · 최소 2점 · Medium 2점 · High 5점)');
  });

  it('does not fabricate ranking values for an old harness-only incident', () => {
    const view = parseConfidenceBreakdown(undefined, {
      status: 'pass',
      overall_score: 79,
      hard_gates: { missing_evidence_trace: false },
    }, 'image_pull_error');

    expect(view?.hasRankingDetails).toBe(false);
    expect(view?.rankingScore).toBeUndefined();
    expect(view?.scoreRows).toEqual([]);
    expect(view?.independentSourceGroups).toEqual([]);
    expect(view?.harness?.overallScore).toBe(79);
  });

  it('returns null when neither diagnostics nor harness data is usable', () => {
    expect(parseConfidenceBreakdown({ unexpected: true }, {})).toBeNull();
  });
});
