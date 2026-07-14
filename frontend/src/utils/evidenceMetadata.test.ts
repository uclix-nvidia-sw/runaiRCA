import { describe, expect, it } from 'vitest';
import { evidenceMetadata } from './evidenceMetadata';

describe('evidenceMetadata', () => {
  it('keeps query coverage separate from the positive signal occurrence', () => {
    expect(evidenceMetadata({
      observation: {
        polarity: 'present',
        coverage: 'scoped',
        entity: 'pod:runai/api',
        observation_window: { start: '2026-07-14T00:00:00Z', end: '2026-07-14T01:00:00Z' },
        evidence_window: { start: '2026-07-14T00:17:00Z', end: '2026-07-14T00:19:00Z' },
      },
    })).toEqual({
      polarity: 'present',
      coverage: 'scoped',
      entity: 'pod:runai/api',
      observationWindow: { start: '2026-07-14T00:00:00Z', end: '2026-07-14T01:00:00Z' },
      evidenceWindow: { start: '2026-07-14T00:17:00Z', end: '2026-07-14T00:19:00Z' },
      typed: true,
    });
  });

  it('does not promote incomplete metadata into a typed observation', () => {
    expect(evidenceMetadata({
      observation: { polarity: 'present', coverage: 'broad' },
    })).toEqual({
      polarity: 'present',
      coverage: undefined,
      entity: undefined,
      observationWindow: undefined,
      evidenceWindow: undefined,
      typed: false,
    });
  });

  it('does not infer semantics from loose result fields', () => {
    expect(evidenceMetadata({ polarity: 'present', coverage: 'scoped' })).toBeNull();
  });
});
