import { Search } from 'lucide-react';
import { useMemo } from 'react';

import type { SimilarIncident } from '../../types';
import { Severity, Status } from '../../utils/formatters';
import { hashForDetail } from '../../utils/routing';

export function SimilarIncidentsPanel({
  items,
  recentCount,
  onOpenIncident,
}: {
  items: SimilarIncident[];
  recentCount: number;
  onOpenIncident: (id: string) => Promise<void>;
}) {
  const visibleItems = useMemo(
    () =>
      [...items]
        .sort((left, right) => {
          if (right.similarity !== left.similarity) return right.similarity - left.similarity;
          return right.created_at.localeCompare(left.created_at);
        })
        .slice(0, 3),
    [items],
  );

  return (
    <section className="similar-panel">
      <div className="section-title">
        <Search size={18} /> Similar Incidents
        <span className="similar-recent-badge">Recent 7d {recentCount}</span>
      </div>
      {visibleItems.length === 0 ? (
        <p className="empty">No similar incident memory yet.</p>
      ) : (
        <div className="similar-list">
          {visibleItems.map((item) => (
            <a
              aria-label={`Open similar incident ${item.incident_id}: ${item.title || item.incident_id}`}
              className="similar-item"
              href={hashForDetail('incident', item.incident_id, 'incidents')}
              key={item.incident_id}
              onClick={(event) => {
                if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
                event.preventDefault();
                void onOpenIncident(item.incident_id);
              }}
            >
              <div className="similar-head">
                <strong>{item.title || item.incident_id}</strong>
                <span>{Math.round(item.similarity * 100)}%</span>
              </div>
              <div className="meta-line">
                <span>{item.incident_id}</span>
                <Severity value={item.severity} />
                <Status value={item.status} />
                <span>{item.positive_feedback} up</span>
                <span>{item.negative_feedback} down</span>
                <span>{item.comment_count} comments</span>
              </div>
              <p>{item.analysis_summary || 'No prior summary captured.'}</p>
            </a>
          ))}
        </div>
      )}
    </section>
  );
}
