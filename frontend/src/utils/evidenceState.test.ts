import { describe, expect, it } from 'vitest';

import { evidenceState } from './evidenceState';

describe('evidenceState', () => {
  it('flags a run whose collectors were all budget-skipped', () => {
    expect(
      evidenceState(['prometheus.analysis_budget', 'loki.analysis_budget'], 0),
    ).toBe('budget_exhausted');
  });

  it('flags partial evidence when some collectors were budget-skipped', () => {
    expect(evidenceState(['loki.analysis_budget'], 4)).toBe('partial');
  });

  it('treats a run with artifacts and no skips as complete', () => {
    expect(evidenceState(['kubernetes.pod_lookup'], 4)).toBe('complete');
    expect(evidenceState(undefined, 2)).toBe('complete');
  });

  it('stays silent for empty runs without budget markers (failed/pending)', () => {
    expect(evidenceState([], 0)).toBeNull();
    expect(evidenceState(undefined, 0)).toBeNull();
  });
});
