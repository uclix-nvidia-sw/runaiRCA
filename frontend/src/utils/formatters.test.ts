import { describe, expect, it } from 'vitest';

import { analysisRunDurationMs, formatDuration } from './formatters';

const CREATED = '2026-07-27T10:00:00Z';

describe('analysisRunDurationMs', () => {
  it('uses first_completed_at when it belongs to this attempt', () => {
    expect(
      analysisRunDurationMs({
        source: 'auto',
        status: 'complete',
        created_at: CREATED,
        updated_at: '2026-07-27T10:05:00Z',
        first_completed_at: '2026-07-27T10:03:00Z',
      }),
    ).toBe(180_000);
  });

  it('falls back to updated_at when the pinned first completion predates this attempt', () => {
    // Re-analysis reuses the run row: created_at is reset, first_completed_at is not.
    expect(
      analysisRunDurationMs({
        source: 'manual',
        status: 'complete',
        created_at: CREATED,
        updated_at: '2026-07-27T10:02:00Z',
        first_completed_at: '2026-07-26T09:00:00Z',
      }),
    ).toBe(120_000);
  });

  it('reports elapsed time for terminal failures', () => {
    expect(
      analysisRunDurationMs({
        source: 'auto',
        status: 'failed',
        created_at: CREATED,
        updated_at: '2026-07-27T10:01:30Z',
      }),
    ).toBe(90_000);
  });

  it('reports nothing while a run is still analyzing', () => {
    expect(
      analysisRunDurationMs({
        source: 'auto',
        status: 'analyzing',
        created_at: CREATED,
        updated_at: '2026-07-27T10:01:00Z',
      }),
    ).toBeNaN();
  });

  it('reports nothing for operator corrections', () => {
    expect(
      analysisRunDurationMs({
        source: 'operator',
        status: 'complete',
        created_at: CREATED,
        updated_at: CREATED,
        first_completed_at: CREATED,
      }),
    ).toBeNaN();
  });

  it('reports nothing without a run', () => {
    expect(analysisRunDurationMs(undefined)).toBeNaN();
  });
});

describe('formatDuration', () => {
  it('hides unusable durations', () => {
    expect(formatDuration(Number.NaN)).toBe('');
    expect(formatDuration(-1)).toBe('');
  });

  it('formats seconds, minutes and hours', () => {
    expect(formatDuration(45_000)).toBe('45s');
    expect(formatDuration(125_000)).toBe('2m 5s');
    expect(formatDuration(3_725_000)).toBe('1h 2m 5s');
  });
});
