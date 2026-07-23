import { ClipboardCheck, Save } from 'lucide-react';
import { useEffect, useReducer, useState } from 'react';

import { fetchAnalysisEvaluation, fetchRootCauseFamilies, saveAnalysisEvaluation } from '../../api';
import { EvaluationReviewInput, EvaluationView } from '../../types';

const DIMENSIONS = [
  ['evidence_grounding', '근거 충실도'],
  ['diagnostic_reasoning', '진단 추론'],
  ['investigation_plan', '조사 계획'],
  ['uncertainty_calibration', '불확실성 보정'],
  ['operational_usefulness', '운영 유용성'],
  ['tool_efficiency', '도구 효율성'],
  ['safety', '안전성'],
] as const;

const EMPTY_SCORES = Object.fromEntries(DIMENSIONS.map(([key]) => [key, 3]));

type EvaluationPanelState = {
  requestedRunID: string;
  requestedAnalysisHash: string;
  view?: EvaluationView;
  evaluationStatus: 'loading' | 'ready' | 'failed';
  catalogStatus: 'loading' | 'ready' | 'failed';
  evaluationError: string;
  catalogError: string;
  caseType: EvaluationReviewInput['case_type'];
  expectedFamily: string;
  expectedFamilies: string[];
  scores: Record<string, number>;
  outcome: EvaluationReviewInput['resolution_outcome'];
  effectiveAction: string;
  notes: string;
  operatorConfirmed: boolean;
};

type EvaluationPanelAction =
  | { type: 'reset'; runID: string; analysisHash: string }
  | { type: 'evaluation_loaded'; view: EvaluationView }
  | { type: 'evaluation_failed'; message: string }
  | { type: 'catalog_loaded'; families: string[] }
  | { type: 'catalog_failed'; message: string }
  | { type: 'case_type_changed'; value: EvaluationReviewInput['case_type'] }
  | { type: 'expected_family_changed'; value: string }
  | { type: 'score_changed'; key: string; value: number }
  | { type: 'outcome_changed'; value: EvaluationReviewInput['resolution_outcome'] }
  | { type: 'effective_action_changed'; value: string }
  | { type: 'notes_changed'; value: string }
  | { type: 'operator_confirmed_changed'; value: boolean }
  | { type: 'review_saved'; review: NonNullable<EvaluationView['my_review']> };

export function initialEvaluationPanelState(): EvaluationPanelState {
  return {
    requestedRunID: '',
    requestedAnalysisHash: '',
    evaluationStatus: 'loading',
    catalogStatus: 'loading',
    evaluationError: '',
    catalogError: '',
    caseType: 'known',
    expectedFamily: '',
    expectedFamilies: [],
    scores: { ...EMPTY_SCORES },
    outcome: 'unknown',
    effectiveAction: '',
    notes: '',
    operatorConfirmed: false,
  };
}

function missingSavedFamilyMessage(family: string) {
  return `Saved expected family "${family}" is no longer in the configured catalog.`;
}

export function evaluationPanelReducer(
  state: EvaluationPanelState,
  action: EvaluationPanelAction,
): EvaluationPanelState {
  switch (action.type) {
    case 'reset':
      return {
        ...initialEvaluationPanelState(),
        requestedRunID: action.runID,
        requestedAnalysisHash: action.analysisHash,
      };
    case 'evaluation_loaded': {
      const review = action.view.my_review;
      const savedFamily = review?.expected_family || '';
      const savedFamilyMissing = state.catalogStatus === 'ready' &&
        Boolean(savedFamily) && !state.expectedFamilies.includes(savedFamily);
      return {
        ...state,
        view: action.view,
        evaluationStatus: 'ready',
        evaluationError: '',
        caseType: review?.case_type || 'known',
        expectedFamily: savedFamilyMissing ? '' : savedFamily,
        scores: { ...EMPTY_SCORES, ...(review?.scores || {}) },
        outcome: review?.resolution_outcome || 'unknown',
        effectiveAction: review?.effective_action || '',
        notes: review?.notes || '',
        operatorConfirmed: review?.operator_confirmed || false,
        catalogError: savedFamilyMissing ? missingSavedFamilyMessage(savedFamily) : state.catalogError,
      };
    }
    case 'evaluation_failed':
      return { ...state, view: undefined, evaluationStatus: 'failed', evaluationError: action.message };
    case 'catalog_loaded': {
      const savedFamilyMissing = Boolean(state.expectedFamily) && !action.families.includes(state.expectedFamily);
      return {
        ...state,
        catalogStatus: 'ready',
        expectedFamilies: action.families,
        expectedFamily: savedFamilyMissing ? '' : state.expectedFamily,
        catalogError: savedFamilyMissing ? missingSavedFamilyMessage(state.expectedFamily) : '',
      };
    }
    case 'catalog_failed':
      // A catalog outage must not erase the operator's saved family or the
      // independently loaded evaluation form.
      return { ...state, catalogStatus: 'failed', catalogError: action.message };
    case 'case_type_changed':
      return {
        ...state,
        caseType: action.value,
        expectedFamily: action.value === 'novel' ? '' : state.expectedFamily,
        // Operator confirmation is only valid for known/compositional cases.
        operatorConfirmed: action.value === 'known' || action.value === 'compositional' ? state.operatorConfirmed : false,
      };
    case 'expected_family_changed':
      return { ...state, expectedFamily: action.value };
    case 'score_changed':
      return { ...state, scores: { ...state.scores, [action.key]: action.value } };
    case 'outcome_changed':
      return { ...state, outcome: action.value };
    case 'effective_action_changed':
      return { ...state, effectiveAction: action.value };
    case 'notes_changed':
      return { ...state, notes: action.value };
    case 'operator_confirmed_changed':
      return { ...state, operatorConfirmed: action.value };
    case 'review_saved':
      return { ...state, view: state.view ? { ...state.view, my_review: action.review } : state.view };
  }
}

export function evaluationPanelCanSave(
  state: EvaluationPanelState,
  runID: string,
  analysisHash: string,
) {
  return state.evaluationStatus === 'ready' && Boolean(state.view) &&
    state.requestedRunID === runID && state.requestedAnalysisHash === analysisHash;
}

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
  const [state, dispatch] = useReducer(
    evaluationPanelReducer,
    undefined,
    initialEvaluationPanelState,
  );
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState('');
  const {
    view,
    evaluationStatus,
    catalogStatus,
    evaluationError,
    catalogError,
    caseType,
    expectedFamily,
    expectedFamilies,
    scores,
    outcome,
    effectiveAction,
    notes,
    operatorConfirmed,
  } = state;

  useEffect(() => {
    if (!runID || !analysisHash) return;
    let cancelled = false;
    dispatch({ type: 'reset', runID, analysisHash });
    setSaveError('');

    void fetchAnalysisEvaluation(runID).then((next) => {
      if (!cancelled) dispatch({ type: 'evaluation_loaded', view: next });
    }).catch((err: unknown) => {
      if (!cancelled) {
        dispatch({
          type: 'evaluation_failed',
          message: err instanceof Error ? err.message : 'Failed to load evaluation.',
        });
      }
    });

    void fetchRootCauseFamilies().then((families) => {
      if (!cancelled) dispatch({ type: 'catalog_loaded', families });
    }).catch((err: unknown) => {
      if (!cancelled) {
        const message = err instanceof Error ? err.message : 'Failed to load root-cause family catalog.';
        dispatch({ type: 'catalog_failed', message: `Root-cause family catalog unavailable: ${message}` });
      }
    });
    return () => { cancelled = true; };
  }, [runID, analysisHash]);

  if (!runID || !analysisHash) return null;
  const evaluationReady = evaluationPanelCanSave(state, runID, analysisHash);
  const catalogLoading = catalogStatus === 'loading';
  const catalogUnavailable = catalogStatus === 'failed';
  const familyOptions = expectedFamily && !expectedFamilies.includes(expectedFamily)
    ? [expectedFamily, ...expectedFamilies]
    : expectedFamilies;
  const hardGates = harness?.hard_gates as Record<string, boolean> | undefined;
  const preview = view?.knowledge_preview;
  const confirmAvailable = Boolean(preview) && preview!.outcome !== 'ready' && preview!.outcome !== 'not_approved' &&
    (caseType === 'known' || caseType === 'compositional') && Boolean(expectedFamily);
  const confirmActive = confirmAvailable && operatorConfirmed;
  const confirmNeedsNote = confirmActive && !notes.trim();
  const save = async () => {
    if (!evaluationReady || confirmNeedsNote) return;
    setBusy(true);
    setSaveError('');
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
        operator_confirmed: confirmActive,
      });
      dispatch({ type: 'review_saved', review });
      // Refresh the view so the knowledge-ingestion preview reflects the saved review.
      const refreshed = await fetchAnalysisEvaluation(runID);
      dispatch({ type: 'evaluation_loaded', view: refreshed });
      await onSaved();
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save evaluation.');
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
      {view?.knowledge_preview && (
        <div
          className={`knowledge-preview knowledge-preview-${view.knowledge_preview.outcome}`}
          aria-label="Knowledge ingestion preview"
        >
          <strong>Knowledge ingestion</strong>
          {view.knowledge_preview.outcome === 'ready' ? (
            <span>
              Will be ingested — {view.knowledge_preview.family || 'family n/a'} · {view.knowledge_preview.evidence_count} evidence · {view.knowledge_preview.probe_count} probe(s)
            </span>
          ) : (
            <span>Not ingested — {view.knowledge_preview.reason || 'not eligible for runtime knowledge'}</span>
          )}
        </div>
      )}
      {evaluationError && <p className="feedback-error">{evaluationError}</p>}
      {catalogError && <p className="feedback-error">{catalogError}</p>}
      {saveError && <p className="feedback-error">{saveError}</p>}
      <form className="evaluation-form" onSubmit={(event) => { event.preventDefault(); void save(); }}>
        <div className="evaluation-basics">
          <label className="evaluation-field">
            <span>Case type</span>
            <select value={caseType} onChange={(event) => {
              const next = event.target.value as EvaluationReviewInput['case_type'];
              dispatch({ type: 'case_type_changed', value: next });
            }} disabled={!evaluationReady || busy}>
              <option value="known">Known</option><option value="compositional">Compositional</option><option value="novel">Novel</option><option value="tool_degraded">Tool degraded</option>
            </select>
          </label>
          {caseType !== 'novel' && (
            <label className="evaluation-field">
              <span>Expected family <small>Optional</small></span>
              <select
                value={expectedFamily}
                onChange={(event) => dispatch({ type: 'expected_family_changed', value: event.target.value })}
                disabled={!evaluationReady || busy || catalogLoading || catalogUnavailable}
              >
                <option value="">
                  {catalogLoading ? 'Loading families…' : catalogUnavailable ? 'Family catalog unavailable' : 'Not specified'}
                </option>
                {familyOptions.map((family) => (
                  <option key={family} value={family}>{family.split('_').join(' ')}</option>
                ))}
              </select>
            </label>
          )}
        </div>

        <fieldset className="evaluation-score-section">
          <legend>RCA quality scores</legend>
          <div className="evaluation-scores">
            {DIMENSIONS.map(([key, label]) => (
              <label className="evaluation-score-field" key={key}>
                <span>{label}</span>
                <select
                  value={scores[key]}
                  onChange={(event) => dispatch({ type: 'score_changed', key, value: Number(event.target.value) })}
                  disabled={!evaluationReady || busy}
                >
                  {[0, 1, 2, 3, 4, 5].map((value) => <option key={value} value={value}>{value}</option>)}
                </select>
              </label>
            ))}
          </div>
        </fieldset>

        <div className="evaluation-outcome-grid">
          <label className="evaluation-field">
            <span>Resolution outcome</span>
            <select
              value={outcome}
              onChange={(event) => dispatch({
                type: 'outcome_changed',
                value: event.target.value as EvaluationReviewInput['resolution_outcome'],
              })}
              disabled={!evaluationReady || busy}
            >
              <option value="unknown">Unknown</option><option value="resolved">Resolved</option><option value="mitigated">Mitigated</option><option value="ineffective">Ineffective</option>
            </select>
          </label>
          <label className="evaluation-field">
            <span>Effective action</span>
            <input
              value={effectiveAction}
              onChange={(event) => dispatch({ type: 'effective_action_changed', value: event.target.value })}
              placeholder="Only if an action actually helped"
              disabled={!evaluationReady || busy}
            />
          </label>
        </div>

        {confirmAvailable && (
          <label className="evaluation-field evaluation-confirm">
            <span className="evaluation-confirm-row">
              <input
                type="checkbox"
                checked={operatorConfirmed}
                onChange={(event) => dispatch({ type: 'operator_confirmed_changed', value: event.target.checked })}
                disabled={!evaluationReady || busy}
              />
              <span>Operator-confirm diagnosis · 재현되지 않은 장애를 운영자가 확정</span>
            </span>
            <small>
              프로브가 불확실해 “supported”에 도달하지 못한 근거 기반 가설을 운영자가 확정합니다. 아래 확정 근거를 입력해야 하며, 지지 증거가 전혀 없는 사건은 계속 거부됩니다.
            </small>
          </label>
        )}

        <label className="evaluation-field evaluation-notes">
          <span>Notes{confirmActive ? ' — 필수: 확정 근거 (운영자 확정 시)' : ''}</span>
          <textarea
            value={notes}
            onChange={(event) => dispatch({ type: 'notes_changed', value: event.target.value })}
            rows={3}
            disabled={!evaluationReady || busy}
          />
        </label>
        <div className="evaluation-actions">
          <button className="primary-button evaluation-save" disabled={!evaluationReady || busy || confirmNeedsNote} type="submit">
            <Save size={16} /> {busy ? 'Saving…' : evaluationStatus === 'loading' ? 'Loading evaluation…' : 'Save evaluation'}
          </button>
        </div>
      </form>
    </section>
  );
}
