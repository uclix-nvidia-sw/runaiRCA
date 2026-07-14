import { describe, expect, it } from 'vitest';

import { collectorEvidencePresentation, shouldPresentRunArtifacts } from './analysisPresentation';

describe('collectorEvidencePresentation', () => {
  it('hides retained evidence while a reanalysis is active', () => {
    expect(collectorEvidencePresentation({
      isAnalyzing: true,
      runStatus: 'analyzing',
      firstCompletedAt: '2026-07-14T00:00:00Z',
      artifactCount: 4,
    })).toMatchObject({ hidden: true });
  });

  it('identifies last-good evidence after a failed reanalysis', () => {
    const presentation = collectorEvidencePresentation({
      isAnalyzing: false,
      runStatus: 'failed',
      firstCompletedAt: '2026-07-14T00:00:00Z',
      artifactCount: 4,
    });

    expect(presentation.hidden).toBe(false);
    expect(presentation.notice).toContain('last completed result');
  });

  it('does not claim a prior completion for a first-attempt failure', () => {
    const presentation = collectorEvidencePresentation({
      isAnalyzing: false,
      runStatus: 'failed',
      artifactCount: 2,
    });

    expect(presentation.notice).toContain('partial evidence from the failed attempt');
  });
});

describe('shouldPresentRunArtifacts', () => {
  it('keeps retained or partial artifacts out of global collector summaries', () => {
    expect(shouldPresentRunArtifacts('complete')).toBe(true);
    expect(shouldPresentRunArtifacts('analyzing')).toBe(false);
    expect(shouldPresentRunArtifacts('failed')).toBe(false);
  });
});
