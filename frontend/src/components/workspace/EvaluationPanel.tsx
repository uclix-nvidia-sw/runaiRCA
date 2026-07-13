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
    <section className="feedback-panel evaluation-panel" id="rca-evaluation">
      <div className="section-title"><ClipboardCheck size={18} /> RCA Evaluation</div>
      <div className="evaluation-summary" aria-label="Evaluation summary">
        {harness && (
          <p>
            <strong>Harness</strong>
            <span>{String(harness.status || 'unknown')} · score {String(harness.overall_score ?? '—')} · repairs {String(harness.repair_attempts ?? 0)}</span>
          </p>
        )}
        {view && (
          <p>
            <strong>Current-RCA reviews</strong>
            <span>{view.reviews.length} · average {view.average_score.toFixed(1)}/5</span>
          </p>
        )}
      </div>
      {error && <p className="feedback-error">{error}</p>}
      <form className="evaluation-form" onSubmit={(event) => { event.preventDefault(); void save(); }}>
        <div className="evaluation-basics">
          <label className="evaluation-field">
            <span>Case type</span>
            <select value={caseType} onChange={(event) => setCaseType(event.target.value as EvaluationReviewInput['case_type'])}>
              <option value="known">Known</option><option value="compositional">Compositional</option><option value="novel">Novel</option><option value="tool_degraded">Tool degraded</option>
            </select>
          </label>
          {caseType !== 'novel' && (
            <label className="evaluation-field">
              <span>Expected family <small>Optional</small></span>
              <input value={expectedFamily} onChange={(event) => setExpectedFamily(event.target.value)} placeholder="gpu_hardware_error" />
            </label>
          )}
        </div>

        <fieldset className="evaluation-score-section">
          <legend>RCA quality scores</legend>
          <div className="evaluation-scores">
            {DIMENSIONS.map(([key, label]) => (
              <label className="evaluation-score-field" key={key}>
                <span>{label}</span>
                <select value={scores[key]} onChange={(event) => setScores((current) => ({ ...current, [key]: Number(event.target.value) }))}>
                  {[0, 1, 2, 3, 4, 5].map((value) => <option key={value} value={value}>{value}</option>)}
                </select>
              </label>
            ))}
          </div>
        </fieldset>

        <div className="evaluation-outcome-grid">
          <label className="evaluation-field">
            <span>Resolution outcome</span>
            <select value={outcome} onChange={(event) => setOutcome(event.target.value as EvaluationReviewInput['resolution_outcome'])}>
              <option value="unknown">Unknown</option><option value="resolved">Resolved</option><option value="mitigated">Mitigated</option><option value="ineffective">Ineffective</option>
            </select>
          </label>
          <label className="evaluation-field">
            <span>Effective action</span>
            <input value={effectiveAction} onChange={(event) => setEffectiveAction(event.target.value)} placeholder="Only if an action actually helped" />
          </label>
        </div>

        <label className="evaluation-field evaluation-notes">
          <span>Notes</span>
          <textarea value={notes} onChange={(event) => setNotes(event.target.value)} rows={3} />
        </label>
        <div className="evaluation-actions">
          <button className="primary-button evaluation-save" disabled={busy} type="submit"><Save size={16} /> {busy ? 'Saving…' : 'Save evaluation'}</button>
        </div>
      </form>
    </section>
  );
}
