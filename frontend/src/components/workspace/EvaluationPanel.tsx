import { ClipboardCheck, Save } from 'lucide-react';
import { useEffect, useState } from 'react';

import { fetchAnalysisEvaluation, saveAnalysisEvaluation } from '../../api';
import { EvaluationReviewInput, EvaluationView } from '../../types';

const DIMENSIONS = [
  ['evidence_grounding', 'Evidence grounding'],
  ['diagnostic_reasoning', 'Diagnostic reasoning'],
  ['investigation_plan', 'Investigation plan'],
  ['uncertainty_calibration', 'Uncertainty calibration'],
  ['operational_usefulness', 'Operational usefulness'],
  ['tool_efficiency', 'Tool efficiency'],
  ['safety', 'Safety'],
] as const;

const EMPTY_SCORES = Object.fromEntries(DIMENSIONS.map(([key]) => [key, 3]));

export function EvaluationPanel({
  runID,
  analysisHash,
  harness,
  onSaved,
}: {
  runID?: string;
  analysisHash?: string;
  harness?: Record<string, unknown>;
  onSaved: () => Promise<void> | void;
}) {
  const [view, setView] = useState<EvaluationView>();
  const [caseType, setCaseType] = useState<EvaluationReviewInput['case_type']>('known');
  const [expectedFamily, setExpectedFamily] = useState('');
  const [scores, setScores] = useState<Record<string, number>>(EMPTY_SCORES);
  const [outcome, setOutcome] = useState<EvaluationReviewInput['resolution_outcome']>('unknown');
  const [effectiveAction, setEffectiveAction] = useState('');
  const [notes, setNotes] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!runID || !analysisHash) return;
    void fetchAnalysisEvaluation(runID).then((next) => {
      setView(next);
      const review = next.my_review;
      if (!review) return;
      setCaseType(review.case_type);
      setExpectedFamily(review.expected_family || '');
      setScores({ ...EMPTY_SCORES, ...review.scores });
      setOutcome(review.resolution_outcome);
      setEffectiveAction(review.effective_action || '');
      setNotes(review.notes || '');
    }).catch((err: unknown) => setError(err instanceof Error ? err.message : 'Failed to load evaluation.'));
  }, [runID, analysisHash]);

  if (!runID || !analysisHash) return null;
  const hardGates = harness?.hard_gates as Record<string, boolean> | undefined;
  const save = async () => {
    setBusy(true);
    setError('');
    try {
      const review = await saveAnalysisEvaluation(runID, {
        analysis_hash: analysisHash,
        case_type: caseType,
        expected_family: expectedFamily,
        scores,
        hard_gates: hardGates || {},
        resolution_outcome: outcome,
        effective_action: effectiveAction,
        notes,
      });
      setView((current) => current ? { ...current, my_review: review } : current);
      await onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save evaluation.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="feedback-panel" id="rca-evaluation">
      <div className="section-title"><ClipboardCheck size={18} /> RCA Evaluation</div>
      {harness && (
        <p className="empty">
          Harness: {String(harness.status || 'unknown')} · score {String(harness.overall_score ?? '—')} · repairs {String(harness.repair_attempts ?? 0)}
        </p>
      )}
      {view && <p className="empty">Current-RCA reviews: {view.reviews.length} · average {view.average_score.toFixed(1)}/5</p>}
      {error && <p className="feedback-error">{error}</p>}
      <label>Case type
        <select value={caseType} onChange={(event) => setCaseType(event.target.value as EvaluationReviewInput['case_type'])}>
          <option value="known">Known</option><option value="compositional">Compositional</option><option value="novel">Novel</option><option value="tool_degraded">Tool degraded</option>
        </select>
      </label>
      {caseType !== 'novel' && <label>Expected family (optional)
        <input value={expectedFamily} onChange={(event) => setExpectedFamily(event.target.value)} placeholder="gpu_hardware_error" />
      </label>}
      <div className="evaluation-scores">
        {DIMENSIONS.map(([key, label]) => <label key={key}>{label}
          <select value={scores[key]} onChange={(event) => setScores((current) => ({ ...current, [key]: Number(event.target.value) }))}>
            {[0, 1, 2, 3, 4, 5].map((value) => <option key={value} value={value}>{value}</option>)}
          </select>
        </label>)}
      </div>
      <label>Resolution outcome
        <select value={outcome} onChange={(event) => setOutcome(event.target.value as EvaluationReviewInput['resolution_outcome'])}>
          <option value="unknown">Unknown</option><option value="resolved">Resolved</option><option value="mitigated">Mitigated</option><option value="ineffective">Ineffective</option>
        </select>
      </label>
      <label>Effective action
        <input value={effectiveAction} onChange={(event) => setEffectiveAction(event.target.value)} placeholder="Only if an action actually helped" />
      </label>
      <label>Notes
        <textarea value={notes} onChange={(event) => setNotes(event.target.value)} rows={3} />
      </label>
      <button className="artifact-toggle compact-artifact-toggle" disabled={busy} onClick={() => void save()} type="button"><Save size={16} /> {busy ? 'Saving…' : 'Save evaluation'}</button>
    </section>
  );
}
