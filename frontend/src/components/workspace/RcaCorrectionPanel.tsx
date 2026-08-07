// Presentation only: every field, its catalog state, and the submit gate come
// from useRcaCorrection, which lives in the parent so a half-written correction
// survives closing this panel.
import { FileText } from 'lucide-react';

import type { RcaCorrection } from './rcaCorrection';

export function RcaCorrectionPanel({
  correction,
  busyAction,
}: {
  correction: RcaCorrection;
  busyAction: string;
}) {
  const busy = Boolean(busyAction);
  return (
    <section className="rca-correction-panel evaluation-panel" aria-label="RCA correction">
      <div className="section-title"><FileText size={18} /> RCA 수정</div>
      {correction.error && <p className="feedback-error">{correction.error}</p>}
      <form className="evaluation-form" onSubmit={(event) => { event.preventDefault(); void correction.save(); }}>
        <label className="evaluation-field">
          <span>Root-cause family</span>
          <select
            ref={correction.familyRef}
            value={correction.family}
            onChange={(event) => correction.setFamily(event.target.value)}
            disabled={correction.catalogStatus !== 'ready' || busy}
            required
          >
            <option value="">
              {correction.catalogStatus === 'loading'
                ? 'Loading families…'
                : correction.catalogStatus === 'failed'
                  ? 'Family catalog unavailable'
                  : 'Select family'}
            </option>
            {correction.families.map((family) => (
              <option key={family} value={family}>{family.split('_').join(' ')}</option>
            ))}
          </select>
        </label>
        <label className="evaluation-field">
          <span>New cause <small>Optional; leave blank to use the catalog family</small></span>
          <input value={correction.newCause} onChange={(event) => { correction.setNewCause(event.target.value); correction.setFamily(''); }} disabled={busy} maxLength={200} />
          {correction.suggestions && (
            <small>
              {correction.suggestions.catalog.map((family) => <button key={family} type="button" className="link-button" onClick={() => { correction.setFamily(family); correction.setNewCause(''); }}>{family}</button>)}
              {correction.suggestions.novel.map((item) => <button key={item.family} type="button" className="link-button" onClick={() => { correction.setFamily(item.family); correction.setNewCause(''); }}>{item.mechanism || item.family}</button>)}
              {correction.newCause.trim() && <> New slug: <code>{correction.suggestions.slug}</code></>}
            </small>
          )}
        </label>
        <label className="evaluation-field">
          <span>RCA summary</span>
          <textarea
            value={correction.summary}
            onChange={(event) => correction.setSummary(event.target.value)}
            disabled={busy}
            required
          />
        </label>
        <label className="evaluation-field">
          <span>Actions <small>One action per line</small></span>
          <textarea
            value={correction.actions}
            onChange={(event) => correction.setActions(event.target.value)}
            disabled={busy}
          />
        </label>
        <div className="evaluation-actions">
          <button
            className="ghost-button"
            disabled={busy}
            onClick={() => correction.setOpen(false)}
            type="button"
          >
            Cancel
          </button>
          <button
            className={`primary-button evaluation-save ${busyAction === 'rca-correction' ? 'is-busy' : ''}`}
            disabled={busy || !correction.submittable}
            type="submit"
          >
            {busyAction === 'rca-correction' ? 'Saving...' : 'Save'}
          </button>
        </div>
      </form>
    </section>
  );
}
