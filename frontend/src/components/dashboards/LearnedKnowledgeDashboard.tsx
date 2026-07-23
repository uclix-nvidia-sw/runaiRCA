import { CheckCircle2, FileSearch, PackageCheck, RotateCcw, ShieldCheck, XCircle } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';

import {
  decideKnowledgeCandidate,
  fetchKnowledgeCandidates,
  fetchKnowledgePackages,
  fetchProbeMetrics,
  fetchKnowledgeRuntimeStatus,
  retireKnowledgePackage,
} from '../../api';
import { KnowledgeCandidate, KnowledgePackage, KnowledgeRuntimeSnapshot, ProbeMetricsSnapshot } from '../../types';
import { formatTime, Status } from '../../utils/formatters';
import { Metric } from '../common/UiParts';

type CandidateFilter = 'all' | 'generated' | 'validation_failed' | 'ready_for_review' | 'shadow' | 'active' | 'rejected' | 'superseded' | 'retired';
type CandidateAction = 'approve' | 'shadow' | 'activate' | 'reject';
type OccurrenceFilter = 'all' | 'single' | 'repeated';

const EMPTY_RUNTIME: KnowledgeRuntimeSnapshot = {
  revision: '',
  packages: [],
};

const EMPTY_PROBE_METRICS: ProbeMetricsSnapshot = { case_count: 0, metrics: [] };

export function LearnedKnowledgeDashboard({ query, refreshKey }: { query: string; refreshKey: number }) {
  const [candidates, setCandidates] = useState<KnowledgeCandidate[]>([]);
  const [packages, setPackages] = useState<KnowledgePackage[]>([]);
  const [runtime, setRuntime] = useState<KnowledgeRuntimeSnapshot>(EMPTY_RUNTIME);
  const [probeMetrics, setProbeMetrics] = useState<ProbeMetricsSnapshot>(EMPTY_PROBE_METRICS);
  const [selectedID, setSelectedID] = useState('');
  // Default to the actionable queue: superseded/failed generations are audit
  // history and drowned the one candidate that actually needs a decision.
  const [filter, setFilter] = useState<CandidateFilter>('ready_for_review');
  const [familyFilter, setFamilyFilter] = useState('all');
  const [kindFilter, setKindFilter] = useState('all');
  const [occurrenceFilter, setOccurrenceFilter] = useState<OccurrenceFilter>('all');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busyID, setBusyID] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [nextCandidates, nextPackages, nextRuntime, nextProbeMetrics] = await Promise.all([
        fetchKnowledgeCandidates(),
        fetchKnowledgePackages(),
        fetchKnowledgeRuntimeStatus(),
        fetchProbeMetrics(),
      ]);
      setCandidates(nextCandidates);
      setPackages(nextPackages);
      setRuntime(nextRuntime);
      setProbeMetrics(nextProbeMetrics);
      setSelectedID((current) => current || nextCandidates[0]?.candidate_id || '');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Learned knowledge is unavailable.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load, refreshKey]);

  const candidateFamilies = useMemo(
    () => Array.from(new Set(candidates.map((item) => item.root_cause_family).filter((value): value is string => Boolean(value)))).sort(),
    [candidates],
  );
  const candidateKinds = useMemo(
    () => Array.from(new Set(candidates.map((item) => item.kind).filter((value): value is string => Boolean(value)))).sort(),
    [candidates],
  );

  const visibleCandidates = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return candidates.filter((candidate) => {
      if (filter !== 'all' && candidate.status !== filter) return false;
      if (familyFilter !== 'all' && candidate.root_cause_family !== familyFilter) return false;
      if (kindFilter !== 'all' && candidate.kind !== kindFilter) return false;
      const repeated = (candidate.supporting_case_count ?? 1) > 1;
      if (occurrenceFilter === 'single' && repeated) return false;
      if (occurrenceFilter === 'repeated' && !repeated) return false;
      if (!normalizedQuery) return true;
      return [
        candidate.title,
        candidate.summary,
        candidate.candidate_id,
        candidate.incident_id,
        candidate.root_cause_family,
        candidate.kind,
      ].some((value) => value?.toLowerCase().includes(normalizedQuery));
    });
  }, [candidates, familyFilter, filter, kindFilter, occurrenceFilter, query]);

  const selected = visibleCandidates.find((candidate) => candidate.candidate_id === selectedID) ?? visibleCandidates[0];
  const pendingCount = candidates.filter((candidate) => candidate.status === 'ready_for_review').length;
  const activePackages = packages.filter((item) => item.status === 'active');
  const mirroredCount = activePackages.filter((item) => item.mirror_status === 'synced').length;
  const mirrorErrorCount = activePackages.filter((item) => item.mirror_status === 'error').length;
  const latestMirrorUpdate = activePackages.reduce<string | undefined>((latest, item) => {
    if (!item.mirror_updated_at || (latest && latest >= item.mirror_updated_at)) return latest;
    return item.mirror_updated_at;
  }, undefined);
  const matchingPackage = selected?.root_cause_family
    ? activePackages.find((item) => item.root_cause_family === selected.root_cause_family)
    : undefined;

  const decide = async (candidate: KnowledgeCandidate, action: CandidateAction) => {
    const label = action === 'approve' ? 'approve' : 'reject';
    if (!window.confirm(`${label[0].toUpperCase()}${label.slice(1)} this incident-derived knowledge candidate?`)) return;
    setBusyID(candidate.candidate_id);
    try {
      await decideKnowledgeCandidate(candidate.candidate_id, action);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : `Could not ${label} candidate.`);
    } finally {
      setBusyID('');
    }
  };

  const retire = async (item: KnowledgePackage) => {
    if (!window.confirm(`Retire ${item.title}? It will no longer be active at runtime.`)) return;
    setBusyID(item.package_id);
    try {
      await retireKnowledgePackage(item.package_id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not retire package.');
    } finally {
      setBusyID('');
    }
  };

  return (
    <div className="knowledge-dashboard">
      <section className="metric-row">
        <Metric label="Ready for review" value={pendingCount} />
        <Metric label="Active packages" value={activePackages.length} />
        <Metric label="Mirrors synced" value={`${mirroredCount}/${activePackages.length}`} />
        <Metric label="Mirror errors" value={mirrorErrorCount} />
        <Metric label="Probe templates observed" value={probeMetrics.metrics.length} />
      </section>

      {error && <div className="error-banner">{error}</div>}

      <section className="knowledge-status-strip" aria-label="Knowledge runtime status">
        <div>
          <ShieldCheck size={18} aria-hidden="true" />
          <span><strong>Incident-derived only</strong> Candidates are created from completed RCA evidence and are immutable in review.</span>
        </div>
        <span>Runtime revision: <code>{runtime.revision || 'not reported'}</code></span>
        <span>Latest mirror update: {latestMirrorUpdate ? formatTime(latestMirrorUpdate) : 'not reported'}</span>
      </section>

      <div className="knowledge-review-grid">
        <section className="knowledge-panel candidate-list-panel">
          <div className="knowledge-panel-head">
            <div>
              <p className="eyebrow">Candidate queue</p>
              <h3>Review candidates</h3>
            </div>
            <div className="knowledge-filters">
              <label className="knowledge-filter">
                <span className="sr-only">Candidate status</span>
                <select value={filter} onChange={(event) => setFilter(event.target.value as CandidateFilter)}>
                  <option value="all">All statuses</option>
                  <option value="generated">Generated</option>
                  <option value="validation_failed">Validation failed</option>
                  <option value="ready_for_review">Ready for review</option>
                  <option value="shadow">Shadow</option>
                  <option value="active">Active</option>
                  <option value="rejected">Rejected</option>
                  <option value="superseded">Superseded</option>
                  <option value="retired">Retired</option>
                </select>
              </label>
              <label className="knowledge-filter">
                <span className="sr-only">Candidate family</span>
                <select value={familyFilter} onChange={(event) => setFamilyFilter(event.target.value)}>
                  <option value="all">All families</option>
                  {candidateFamilies.map((family) => <option key={family} value={family}>{family}</option>)}
                </select>
              </label>
              <label className="knowledge-filter">
                <span className="sr-only">Candidate kind</span>
                <select value={kindFilter} onChange={(event) => setKindFilter(event.target.value)}>
                  <option value="all">All kinds</option>
                  {candidateKinds.map((kind) => <option key={kind} value={kind}>{kind}</option>)}
                </select>
              </label>
              <label className="knowledge-filter">
                <span className="sr-only">Candidate occurrence</span>
                <select value={occurrenceFilter} onChange={(event) => setOccurrenceFilter(event.target.value as OccurrenceFilter)}>
                  <option value="all">All occurrence</option>
                  <option value="single">Single case</option>
                  <option value="repeated">Repeated cases</option>
                </select>
              </label>
            </div>
          </div>
          <div className="knowledge-candidate-list">
            {visibleCandidates.map((candidate) => (
              <button
                aria-pressed={selected?.candidate_id === candidate.candidate_id}
                className={`knowledge-candidate ${selected?.candidate_id === candidate.candidate_id ? 'is-selected' : ''}`}
                key={candidate.candidate_id}
                onClick={() => setSelectedID(candidate.candidate_id)}
                type="button"
              >
                <span className="knowledge-candidate-topline"><Status value={candidate.status} /><time>{formatTime(candidate.created_at || '')}</time></span>
                <strong>{candidate.title || 'Untitled incident-derived candidate'}</strong>
                <span>{candidate.root_cause_family || 'Unclassified family'} · {candidate.kind || 'kind not reported'} · {supportingCaseLabel(candidate)}</span>
              </button>
            ))}
            {!loading && visibleCandidates.length === 0 && <EmptyState text="No candidates match this review filter." />}
            {loading && <EmptyState text="Loading incident-derived candidates…" />}
          </div>
        </section>

        <section className="knowledge-panel candidate-detail-panel">
          {selected ? (
            <CandidateDetail candidate={selected} matchingPackage={matchingPackage} busy={busyID === selected.candidate_id} onDecide={decide} />
          ) : (
            <EmptyState text="Select a candidate to inspect its evidence and provenance." />
          )}
        </section>
      </div>

      <section className="knowledge-panel knowledge-packages-panel">
        <div className="knowledge-panel-head">
          <div>
            <p className="eyebrow">Runtime inventory</p>
            <h3>Active knowledge packages</h3>
          </div>
          <span className="knowledge-package-count"><PackageCheck size={16} /> {activePackages.length} active</span>
        </div>
        <div className="knowledge-package-list">
          {activePackages.map((item) => (
            <article className="knowledge-package" key={item.package_id}>
              <div>
                <strong>{item.title || item.package_id}</strong>
                <span>{item.root_cause_family || 'Incident-derived package'} · confidence {formatConfidence(item.confidence)}</span>
                <small>Published {item.published_at ? formatTime(item.published_at) : 'not reported'} · Candidate {item.candidate_id || 'not reported'}</small>
              </div>
              <div className="knowledge-package-status">
                <Status value={item.runtime_status || item.status} />
                <Status value={item.mirror_status || 'pending'} />
                <button className="ghost-button danger-button" disabled={busyID === item.package_id} onClick={() => void retire(item)} type="button">
                  <RotateCcw size={15} /> {busyID === item.package_id ? 'Retiring…' : 'Retire'}
                </button>
              </div>
              {(item.mirror_updated_at || item.mirror_last_error) && (
                <small className="knowledge-mirror-meta">
                  {item.mirror_updated_at && `Mirror checked ${formatTime(item.mirror_updated_at)}`}
                  {item.mirror_updated_at && item.mirror_last_error && ' · '}
                  {item.mirror_last_error && `Mirror error: ${item.mirror_last_error}`}
                </small>
              )}
            </article>
          ))}
          {!loading && activePackages.length === 0 && <EmptyState text="No active knowledge packages are reported by the runtime." />}
        </div>
      </section>

      <section className="knowledge-panel knowledge-packages-panel">
        <div className="knowledge-panel-head">
          <div>
            <p className="eyebrow">Probe feedback</p>
            <h3>Observed probe utility</h3>
          </div>
          <span className="knowledge-package-count"><FileSearch size={16} /> {probeMetrics.case_count} approved cases</span>
        </div>
        <div className="knowledge-evidence-list">
          {probeMetrics.metrics.map((metric) => (
            <article className="knowledge-evidence" key={metric.template_id}>
              <div><strong>{metric.template_id}</strong><span>{metric.executions} executions across {metric.case_count} cases</span></div>
              <p>{metric.supports} supported · {metric.refutes} refuted · {metric.inconclusive} inconclusive · final diagnosis support {metric.final_diagnosis_supported}/{metric.final_diagnosis_tests}</p>
            </article>
          ))}
          {!loading && probeMetrics.metrics.length === 0 && <EmptyState text="No approved trace-v3 probe executions are available yet." />}
        </div>
      </section>
    </div>
  );
}

function CandidateDetail({
  candidate,
  matchingPackage,
  busy,
  onDecide,
}: {
  candidate: KnowledgeCandidate;
  matchingPackage?: KnowledgePackage;
  busy: boolean;
  onDecide: (candidate: KnowledgeCandidate, action: CandidateAction) => Promise<void>;
}) {
  const evidence = candidate.evidence_summaries ?? [];
  const canReview = candidate.status === 'ready_for_review';
  const canActivate = candidate.status === 'shadow';
  const provenance = safeProvenanceEntries(candidate.provenance);
  return (
    <>
      <div className="knowledge-panel-head candidate-detail-head">
        <div>
          <p className="eyebrow">Candidate detail</p>
          <h3>{candidate.title || 'Untitled incident-derived candidate'}</h3>
          <span>{candidate.root_cause_family || 'Unclassified family'} · confidence {formatConfidence(candidate.confidence)}</span>
        </div>
        <Status value={candidate.status} />
      </div>
      <div className="knowledge-detail-content">
        <p className="knowledge-summary">{candidate.summary || 'No candidate summary was reported.'}</p>
        <dl className="knowledge-provenance">
          <div><dt>Incident</dt><dd>{candidate.incident_id || 'not reported'}</dd></div>
          <div><dt>Kind</dt><dd>{candidate.kind || 'not reported'}</dd></div>
          <div><dt>Supporting cases</dt><dd>{supportingCaseLabel(candidate)}</dd></div>
          <div><dt>Analysis run</dt><dd>{candidate.analysis_run_id || 'not reported'}</dd></div>
          <div><dt>Analysis hash</dt><dd><code>{candidate.analysis_hash || 'not reported'}</code></dd></div>
          <div><dt>Observed</dt><dd>{candidate.created_at ? formatTime(candidate.created_at) : 'not reported'}</dd></div>
          {candidate.decided_at && <div><dt>Decided</dt><dd>{formatTime(candidate.decided_at)}</dd></div>}
          {candidate.decided_by && <div><dt>Decided by</dt><dd>{candidate.decided_by}</dd></div>}
          {provenance.map(([key, value]) => (
            <div key={key}><dt>{labelFor(key)}</dt><dd>{value}</dd></div>
          ))}
        </dl>

        {candidate.validation_error && <p className="knowledge-validation-error">Validation: {candidate.validation_error}</p>}

        {matchingPackage && <FamilyPackageComparison candidate={candidate} pkg={matchingPackage} />}

        <div className="knowledge-evidence-head"><FileSearch size={17} /> Evidence ({evidence.length})</div>
        <div className="knowledge-evidence-list">
          {evidence.map((item, index) => (
            <article className="knowledge-evidence" key={item.evidence_id || `${item.source}-${index}`}>
              <div><strong>{item.predicate || item.evidence_id || 'Evidence predicate'}</strong><span>{evidenceSourceLabel(item)}</span></div>
              <p>{[item.entity, item.polarity, item.coverage, item.quality].filter(Boolean).join(' · ') || 'Evidence metadata not reported.'}</p>
            </article>
          ))}
          {evidence.length === 0 && <EmptyState text="No evidence summary was reported for this candidate." />}
        </div>
        {candidate.probe_template_ids && candidate.probe_template_ids.length > 0 && (
          <div className="knowledge-probe-ids">
            <strong>Linked probe templates</strong>
            <span>{candidate.probe_template_ids.join(' · ')}</span>
          </div>
        )}
      </div>
      {canReview && (
        <div className="knowledge-review-actions">
          <button className="primary-button" disabled={busy} onClick={() => void onDecide(candidate, 'approve')} type="button">
            <CheckCircle2 size={16} /> {busy ? 'Saving…' : 'Activate now'}
          </button>
          <button className="ghost-button" disabled={busy} onClick={() => void onDecide(candidate, 'shadow')} type="button">
            <FileSearch size={16} /> Shadow first
          </button>
          <button className="ghost-button danger-button" disabled={busy} onClick={() => void onDecide(candidate, 'reject')} type="button">
            <XCircle size={16} /> Reject candidate
          </button>
        </div>
      )}
      {canActivate && (
        <div className="knowledge-review-actions">
          <button className="primary-button" disabled={busy} onClick={() => void onDecide(candidate, 'activate')} type="button">
            <CheckCircle2 size={16} /> {busy ? 'Saving…' : 'Activate shadow package'}
          </button>
        </div>
      )}
    </>
  );
}

function FamilyPackageComparison({ candidate, pkg }: { candidate: KnowledgeCandidate; pkg: KnowledgePackage }) {
  return (
    <section className="knowledge-family-comparison">
      <strong>Active package for this family</strong>
      <span>{pkg.title || pkg.package_id} · {pkg.mirror_status || 'pending'} mirror</span>
      <small>
        Candidate {formatConfidence(candidate.confidence)} confidence · package {formatConfidence(pkg.confidence)} confidence · {pkg.evidence_summaries?.length ?? 0} package evidence summaries
      </small>
    </section>
  );
}

function EmptyState({ text }: { text: string }) {
  return <p className="empty compact-empty">{text}</p>;
}

function labelFor(key: string) {
  return key.replace(/[_-]/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatConfidence(value?: number) {
  if (!Number.isFinite(value)) return 'not reported';
  return value! >= 0 && value! <= 1 ? `${Math.round(value! * 100)}%` : value!.toFixed(2);
}

function safeProvenanceEntries(provenance?: Record<string, unknown>): Array<[string, string]> {
  return Object.entries(provenance ?? []).flatMap(([key, value]) => {
    if (typeof value === 'string' && value.trim()) return [[key, value]];
    if (typeof value === 'number' && Number.isFinite(value)) return [[key, String(value)]];
    if (typeof value === 'boolean') return [[key, String(value)]];
    return [];
  });
}

function evidenceSourceLabel(item: { source?: string; source_group?: string }) {
  const sources = [item.source_group, item.source].filter((value, index, values): value is string => Boolean(value) && values.indexOf(value) === index);
  return sources.length > 0 ? sources.join(' · ') : 'source not reported';
}

function supportingCaseLabel(candidate: KnowledgeCandidate) {
  const count = Math.max(1, candidate.supporting_case_count ?? 1);
  return `${count} supporting case${count === 1 ? '' : 's'}`;
}
