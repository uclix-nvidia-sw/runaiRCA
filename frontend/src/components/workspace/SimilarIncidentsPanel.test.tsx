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
});
