import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { SimilarIncident } from '../../types';
import { SimilarIncidentsPanel } from './SimilarIncidentsPanel';

function similarIncident(incidentID: string, similarity: number): SimilarIncident {
  return {
    incident_id: incidentID,
    title: `Incident ${incidentID}`,
    severity: 'warning',
    status: 'resolved',
    similarity,
    analysis_summary: 'Prior incident summary.',
    positive_feedback: 1,
    negative_feedback: 0,
    comment_count: 0,
    created_at: '2026-07-14T00:00:00Z',
  };
}

describe('SimilarIncidentsPanel', () => {
  it('renders each visible incident as an accessible detail link', () => {
    const markup = renderToStaticMarkup(
      <SimilarIncidentsPanel
        items={[
          similarIncident('INC/older', 0.6),
          similarIncident('INC-closest', 0.95),
        ]}
        recentCount={2}
        onOpenIncident={vi.fn()}
      />,
    );

    expect(markup).toContain('href="#/incidents/incidents/INC-closest"');
    expect(markup).toContain('href="#/incidents/incidents/INC%2Folder"');
    expect(markup).toContain(
      'aria-label="Open similar incident INC-closest: Incident INC-closest"',
    );
    expect(markup.indexOf('INC-closest')).toBeLessThan(markup.indexOf('INC/older'));
  });

  it('falls back to a Korean placeholder when a prior incident has no stored summary', () => {
    // analysis_summary here is Korean by chart default (same field the main
    // RCA Summary panel renders); an English "No prior summary captured."
    // placeholder in the same slot reads as an untranslated fragment on an
    // otherwise-Korean incident panel.
    const noSummary = { ...similarIncident('INC-blank', 0.8), analysis_summary: '' };
    const markup = renderToStaticMarkup(
      <SimilarIncidentsPanel items={[noSummary]} recentCount={1} onOpenIncident={vi.fn()} />,
    );

    expect(markup).toContain('이전 요약이 없습니다.');
    expect(markup).not.toContain('No prior summary captured.');
  });

  it('shows the retrieval index next to the percentage when the backend stamps one', () => {
    const item = { ...similarIncident('INC-dense', 0.97), retrieval_kind: 'dense-semantic' };
    const markup = renderToStaticMarkup(
      <SimilarIncidentsPanel items={[item]} recentCount={1} onOpenIncident={vi.fn()} />,
    );

    expect(markup).toContain('97%');
    expect(markup).toContain('semantic');
    expect(markup).toContain('class="retrieval-kind"');
  });

  it('renders only the percentage when retrieval_kind is absent, with no leftover separator', () => {
    const markup = renderToStaticMarkup(
      <SimilarIncidentsPanel
        items={[similarIncident('INC-plain', 0.78)]}
        recentCount={1}
        onOpenIncident={vi.fn()}
      />,
    );

    expect(markup).toContain('78%');
    expect(markup).not.toContain('retrieval-kind');
    expect(markup).not.toContain('·');
  });

  it('falls back to the raw slug for an unrecognized retrieval_kind instead of dropping it', () => {
    const item = { ...similarIncident('INC-future', 0.6), retrieval_kind: 'future-index-v2' };
    const markup = renderToStaticMarkup(
      <SimilarIncidentsPanel items={[item]} recentCount={1} onOpenIncident={vi.fn()} />,
    );

    expect(markup).toContain('future-index-v2');
  });
});
