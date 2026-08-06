// The live analysis progress feed: one row per agent event, with the
// hypothesis ledger folded into the row that changed it.
import { ChevronDown, ListChecks } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

import { AnalysisProgressEntry, AnalysisRun } from '../../types';
import { safeJSONStringify } from '../../utils/artifactValues';
import { agentLabel, formatTime } from '../../utils/formatters';

export function ProgressTimeline({
  events,
  live,
  run,
}: {
  events: AnalysisProgressEntry[];
  live: boolean;
  run?: AnalysisRun;
}) {
  const [open, setOpen] = useState(live);
  const historyRef = useRef<HTMLOListElement>(null);
  const followsLatestRef = useRef(true);
  const initializedScrollRef = useRef(false);
  const runID = run?.run_id ?? '';

  useEffect(() => {
    if (live) setOpen(true);
  }, [live]);

  useEffect(() => {
    initializedScrollRef.current = false;
    followsLatestRef.current = true;
  }, [runID]);

  useEffect(() => {
    const history = historyRef.current;
    if (!open || !history) return;
    if (!initializedScrollRef.current || (live && followsLatestRef.current)) {
      const frame = window.requestAnimationFrame(() => {
        history.scrollTop = history.scrollHeight;
        initializedScrollRef.current = true;
      });
      return () => window.cancelAnimationFrame(frame);
    }
  }, [events.length, live, open, runID]);

  const handleHistoryScroll = () => {
    const history = historyRef.current;
    if (!history) return;
    const distanceFromLatest = history.scrollHeight - history.scrollTop - history.clientHeight;
    followsLatestRef.current = distanceFromLatest < 48;
  };

  const ledger = latestProgressLedger(events);
  return (
    <section className={`progress-timeline ${live ? 'is-live' : ''}`}>
      <button className="progress-timeline-head" onClick={() => setOpen((value) => !value)} type="button">
        <span>
          <ListChecks size={18} /> Thought Process
        </span>
        <span className="progress-timeline-meta">
          {live ? 'live' : run?.updated_at ? formatTime(run.updated_at) : 'complete'} · {events.length}
          <ChevronDown size={15} />
        </span>
      </button>
      {open && (
        <div className="progress-timeline-body">
          {ledger.length > 0 && (
            <div className="hypothesis-strip">
              {ledger.slice(0, 4).map((item) => {
                // 0.5 with status "open" is the investigator's untouched seed, not a
                // computed probability — showing "50%" on every chip misled operators.
                const seeded = String(item.status || 'open') === 'open' && item.confidence === 0.5;
                return (
                  <span key={String(item.id)} className={`hypothesis-chip status-${String(item.status || 'open')}`}>
                    <strong>{String(item.family || item.id || 'hypothesis').replace(/_/g, ' ')}</strong>
                    {typeof item.confidence === 'number' && !seeded && <em>{Math.round(item.confidence * 100)}%</em>}
                  </span>
                );
              })}
            </div>
          )}
          {events.length === 0 ? (
            <p className="empty">Analysis has started. Waiting for the first reasoning update.</p>
          ) : (
            <>
              <div className="progress-history-hint">
                <span>{events.length} updates</span>
                <span>Scroll up for earlier history</span>
              </div>
              <ol
                aria-label="Thought Process history"
                className="progress-events progress-events-scroll"
                onScroll={handleHistoryScroll}
                ref={historyRef}
              >
                {events.map((event, index) => (
                  <li key={`${event.seq ?? index}-${event.phase ?? 'phase'}`}>
                    <span className="progress-dot" />
                    <div className="progress-event-copy">
                      <div className="progress-event-head">
                        <strong>{progressEventTitle(event)}</strong>
                        <time>{formatProgressTimestamp(event.timestamp)}</time>
                      </div>
                      {event.message && <p>{String(event.message)}</p>}
                      <ProgressEventDetails event={event} />
                    </div>
                  </li>
                ))}
              </ol>
            </>
          )}
        </div>
      )}
    </section>
  );
}

const PROGRESS_BASE_FIELDS = new Set(['seq', 'phase', 'message', 'timestamp']);
const PROGRESS_REQUEST_FIELDS = new Set([
  'target',
  'plan',
  'hypotheses',
  'scope',
  'query',
  'queries',
  'probes',
]);
const PROGRESS_RESPONSE_FIELDS = new Set([
  'collector',
  'collectors',
  'status',
  'summary',
  'top_root_cause',
  'root_cause_candidates',
  'refuted',
  'caveat',
  'next_check',
]);
const PROGRESS_DECISION_FIELDS = new Set([
  'step',
  'action',
  'selected_hypothesis',
  'hypothesis_ledger',
  'hypothesis_updates',
]);

type ProgressDetailGroup = {
  label: string;
  entries: Array<[string, unknown]>;
};

function ProgressEventDetails({ event }: { event: AnalysisProgressEntry }) {
  const groups = progressDetailGroups(event);
  const fieldCount = groups.reduce((total, group) => total + group.entries.length, 0);
  if (fieldCount === 0) return null;
  return (
    <details className="progress-event-details">
      <summary>
        <span>Exchange details</span>
        <span>{fieldCount} field{fieldCount === 1 ? '' : 's'}</span>
      </summary>
      <div className="progress-detail-groups">
        {groups.map((group) => (
          <section key={group.label} className="progress-detail-group">
            <h4>{group.label}</h4>
            {group.entries.map(([key, value]) => (
              <div className="progress-detail-field" key={key}>
                <span>{progressFieldLabel(key)}</span>
                {isProgressScalar(value) ? (
                  <span className="progress-detail-plain">{formatProgressValue(value)}</span>
                ) : (
                  <pre tabIndex={0}>{formatProgressValue(value)}</pre>
                )}
              </div>
            ))}
          </section>
        ))}
      </div>
    </details>
  );
}

function progressDetailGroups(event: AnalysisProgressEntry): ProgressDetailGroup[] {
  const grouped: Record<string, Array<[string, unknown]>> = {
    'Sent context': [],
    'Agent decision': [],
    'Received observation': [],
    'Additional context': [],
  };
  for (const [key, value] of Object.entries(event)) {
    if (PROGRESS_BASE_FIELDS.has(key) || value === undefined || value === null || value === '') {
      continue;
    }
    const label = PROGRESS_REQUEST_FIELDS.has(key)
      ? 'Sent context'
      : PROGRESS_DECISION_FIELDS.has(key)
        ? 'Agent decision'
        : PROGRESS_RESPONSE_FIELDS.has(key)
          ? 'Received observation'
          : 'Additional context';
    grouped[label].push([key, value]);
  }
  return Object.entries(grouped)
    .filter(([, entries]) => entries.length > 0)
    .map(([label, entries]) => ({ label, entries }));
}

function progressFieldLabel(key: string) {
  return key.replace(/_/g, ' ').replace(/\b\w/g, (character) => character.toUpperCase());
}

function formatProgressValue(value: unknown) {
  return typeof value === 'string' ? value : safeJSONStringify(value, 2);
}

function isProgressScalar(value: unknown) {
  return typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean';
}

function latestProgressLedger(events: AnalysisProgressEntry[]) {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const ledger = events[index].hypothesis_ledger;
    if (Array.isArray(ledger)) return ledger as Array<Record<string, unknown>>;
  }
  return [];
}

const PHASE_LABELS: Record<string, string> = {
  enrich: 'Enrichment',
  plan: 'Planning',
  planning: 'Planning',
  evidence: 'Evidence',
  collection: 'Evidence',
  rank: 'Ranking',
  ranking: 'Ranking',
  investigation: 'Investigation',
  self_check: 'Self-check',
  synthesize: 'Synthesis',
  harness: 'Validation',
  reflection: 'Synthesis',
};

function progressEventTitle(event: AnalysisProgressEntry) {
  const rawPhase = String(event.phase || 'progress');
  const phase = PHASE_LABELS[rawPhase] || rawPhase.replace(/_/g, ' ');
  if (event.collector) return `${phase} · ${agentLabel(String(event.collector))}`;
  if (event.selected_hypothesis) return `${phase} · ${String(event.selected_hypothesis)}`;
  return phase;
}

function formatProgressTimestamp(value: unknown) {
  if (typeof value !== 'string' || !value) return '';
  return formatTime(value);
}

