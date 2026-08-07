// The operator's "RCA 수정" form: eleven pieces of state, a catalog fetch, a
// debounced suggestion lookup, and its own focus/Escape handling. It lives in a
// hook rather than a component so the state survives closing the panel — the
// seeding effect below only fills PRISTINE fields precisely so that reopening
// never clobbers an edit in progress.
import { useCallback, useEffect, useRef, useState } from 'react';

import { fetchFamilySuggestions, fetchRootCauseFamilies, rcaCorrection, rcaPin } from '../../api';
import type { AnalysisRun, IncidentDetail } from '../../types';
import { errorMessage, reportActionLines } from '../../utils/artifactValues';
import { parseCorrectionActions } from '../../utils/operatorCorrection';

export type CorrectionCatalogStatus = 'loading' | 'ready' | 'failed';

export type FamilySuggestions = {
  catalog: string[];
  novel: Array<{ family: string; mechanism: string }>;
  slug: string;
};

export function useRcaCorrection({
  incident,
  analysisRun,
  report,
  busyAction,
  setBusyAction,
  onRefresh,
  onReverify,
}: {
  incident: IncidentDetail | null;
  analysisRun?: AnalysisRun;
  report: { analysis_summary?: string; analysis_detail?: string };
  busyAction: string;
  setBusyAction: (value: string) => void;
  onRefresh: () => Promise<void>;
  onReverify: (id: string) => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const [family, setFamily] = useState('');
  const [newCause, setNewCause] = useState('');
  const [suggestions, setSuggestions] = useState<FamilySuggestions>();
  const [summary, setSummary] = useState('');
  const [actions, setActions] = useState('');
  const [catalogStatus, setCatalogStatus] = useState<CorrectionCatalogStatus>('ready');
  const [families, setFamilies] = useState<string[]>([]);
  const [error, setError] = useState('');
  // The pin/re-verify actions below act on the operator RUN this form produced,
  // so they live with it. actionError is theirs; error above is the form's.
  const [actionError, setActionError] = useState('');
  const [pinnedOverride, setPinnedOverride] = useState<boolean>();
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const familyRef = useRef<HTMLSelectElement | null>(null);

  useEffect(() => {
    if (!open) return undefined;
    let cancelled = false;
    setCatalogStatus('loading');
    setError('');
    void fetchRootCauseFamilies().then((loaded) => {
      if (cancelled) return;
      setFamilies(loaded);
      setCatalogStatus('ready');
      // "수정" edits the RCA the operator is looking at: seed the form from
      // the current analysis. Pristine fields only, so reopening the panel
      // never clobbers an in-progress edit.
      if (!family && !newCause && !summary && !actions) {
        const currentFamily = String(incident?.root_cause_family ?? '');
        if (currentFamily && loaded.includes(currentFamily)) {
          setFamily(currentFamily);
        }
        setSummary(report.analysis_summary ?? '');
        setActions(reportActionLines(report.analysis_detail ?? ''));
      }
    }).catch((err: unknown) => {
      if (cancelled) return;
      setCatalogStatus('failed');
      setError(`Root-cause family catalog unavailable: ${errorMessage(err, 'Failed to load catalog.')}`);
    });
    return () => { cancelled = true; };
  }, [open]);

  useEffect(() => {
    if (!newCause.trim()) { setSuggestions(undefined); return undefined; }
    let cancelled = false;
    const handle = window.setTimeout(() => { void fetchFamilySuggestions(newCause).then((value) => { if (!cancelled) setSuggestions(value); }).catch(() => { if (!cancelled) setSuggestions(undefined); }); }, 300);
    return () => { cancelled = true; window.clearTimeout(handle); };
  }, [newCause]);

  const close = useCallback(() => {
    setOpen(false);
    triggerRef.current?.focus();
  }, []);

  useEffect(() => {
    if (!open) return undefined;
    familyRef.current?.focus();

    const handleCorrectionKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      event.stopPropagation();
      close();
    };

    document.addEventListener('keydown', handleCorrectionKeyDown, true);
    return () => document.removeEventListener('keydown', handleCorrectionKeyDown, true);
  }, [open, close]);

  useEffect(() => {
    setPinnedOverride(undefined);
  }, [analysisRun?.run_id]);

  // A draft survives closing the panel on purpose — the seeding effect above
  // fills pristine fields only so reopening never clobbers an edit. It must NOT
  // survive switching to a different incident: the workspace is not remounted
  // between targets, so the draft would otherwise be saved onto the new one.
  const draftFor = useRef<string | undefined>(incident?.incident_id);
  useEffect(() => {
    const id = incident?.incident_id;
    // Skip the null transition rather than recording it: closing the workspace
    // sets incident to null, and reopening the SAME one must still find the
    // draft. Only an actual switch to another incident resets.
    if (!id || draftFor.current === id) return;
    draftFor.current = id;
    setOpen(false);
    setFamily('');
    setNewCause('');
    setSummary('');
    setActions('');
    setSuggestions(undefined);
    setError('');
    setActionError('');
  }, [incident?.incident_id]);

  const isOperatorRun = analysisRun?.source === 'operator';
  const pinned = isOperatorRun && (pinnedOverride ?? analysisRun?.metadata?.pinned === true);

  const togglePin = async () => {
    if (!incident || !isOperatorRun || busyAction) return;
    setBusyAction('rca-pin');
    setActionError('');
    try {
      const run = await rcaPin(incident.incident_id, !pinned);
      setPinnedOverride(run.metadata?.pinned === true);
      await onRefresh();
    } catch (err) {
      setActionError(errorMessage(err, 'Failed to update RCA correction pin.'));
    } finally {
      setBusyAction('');
    }
  };

  const reverify = async () => {
    if (!incident || !pinned || busyAction) return;
    setBusyAction('reverify');
    setActionError('');
    try {
      await onReverify(incident.incident_id);
    } catch (err) {
      setActionError(errorMessage(err, 'Failed to start re-verification.'));
    } finally {
      setBusyAction('');
    }
  };

  const submittable =
    catalogStatus === 'ready' && Boolean(family || newCause.trim()) && Boolean(summary.trim());

  const save = async () => {
    if (!incident || busyAction || !submittable) return;
    setBusyAction('rca-correction');
    setError('');
    try {
      await rcaCorrection(incident.incident_id, {
        ...(newCause.trim() ? { new_cause: newCause.trim() } : { root_cause_family: family }),
        summary: summary.trim(),
        actions: parseCorrectionActions(actions),
      });
      await onRefresh();
      setOpen(false);
      setFamily('');
      setNewCause('');
      setSummary('');
      setActions('');
    } catch (err) {
      setError(errorMessage(err, 'Failed to save RCA correction.'));
    } finally {
      setBusyAction('');
    }
  };

  return {
    open, setOpen, close, triggerRef, familyRef,
    family, setFamily, newCause, setNewCause, summary, setSummary, actions, setActions,
    suggestions, families, catalogStatus, error, submittable, save,
    isOperatorRun, pinned, actionError, togglePin, reverify,
  };
}

export type RcaCorrection = ReturnType<typeof useRcaCorrection>;
