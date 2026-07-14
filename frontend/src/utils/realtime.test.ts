import { describe, expect, it } from 'vitest';

import { appendProgress, clearProgress, resetProgress, updateCompletedProgressRuns } from './realtime';

describe('analysis progress attempt boundaries', () => {
  it('clears retained progress when a reused run starts a new attempt', () => {
    const previous = {
      'ANL-1': [
        { seq: 1, phase: 'plan' },
        { seq: 2, phase: 'self_check' },
      ],
    };

    const reset = resetProgress(previous, {
      type: 'analysis.started',
      data: { run_id: 'ANL-1' },
    });
    const next = appendProgress(reset, {
      type: 'analysis.progress',
      data: { run_id: 'ANL-1', seq: 1, phase: 'plan' },
    });

    expect(next['ANL-1']).toEqual([{ run_id: 'ANL-1', seq: 1, phase: 'plan' }]);
  });

  it('does not clear another run for unrelated events', () => {
    const previous = { 'ANL-1': [{ seq: 1, phase: 'plan' }] };

    expect(resetProgress(previous, {
      type: 'analysis.completed',
      data: { run_id: 'ANL-1' },
    })).toBe(previous);
  });

  it('drops only completed local overrides after authoritative data reloads', () => {
    const previous = {
      'ANL-1': [{ seq: 1, phase: 'stale' }],
      'ANL-2': [{ seq: 2, phase: 'live' }],
    };

    expect(clearProgress(previous, ['ANL-1'])).toEqual({
      'ANL-2': [{ seq: 2, phase: 'live' }],
    });
    expect(previous).toHaveProperty('ANL-1');
  });

  it('does not let an older completion clear a newly started reused run', () => {
    let completedRuns = new Set<string>();
    completedRuns = updateCompletedProgressRuns(completedRuns, {
      type: 'analysis.completed',
      data: { run_id: 'ANL-1' },
    });
    completedRuns = updateCompletedProgressRuns(completedRuns, {
      type: 'analysis.started',
      data: { run_id: 'ANL-1' },
    });
    const nextAttempt = appendProgress(
      resetProgress({ 'ANL-1': [{ seq: 9, phase: 'old' }] }, {
        type: 'analysis.started',
        data: { run_id: 'ANL-1' },
      }),
      {
        type: 'analysis.progress',
        data: { run_id: 'ANL-1', seq: 1, phase: 'new' },
      },
    );

    expect([...completedRuns]).toEqual([]);
    expect(clearProgress(nextAttempt, completedRuns)).toEqual(nextAttempt);
    expect(nextAttempt['ANL-1']).toEqual([{ run_id: 'ANL-1', seq: 1, phase: 'new' }]);
  });
});
