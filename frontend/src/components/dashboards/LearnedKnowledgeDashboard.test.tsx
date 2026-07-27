import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { KnowledgeCandidate } from '../../types';
import { CandidateDetail, IngestionPreview } from './LearnedKnowledgeDashboard';

function candidate(overrides: Partial<KnowledgeCandidate> = {}): KnowledgeCandidate {
  return {
    candidate_id: 'KC-1',
    status: 'ready_for_review',
    payload: {
      mechanism: 'configmap missing at container start',
      compiled: {
        failure_modes: [
          {
            family: 'workload_startup_error',
            symptoms: [
              {
                name: 'configmap missing at container start',
                keywords: ['configmap', 'createcontainerconfigerror'],
                actions: ['Recreate the missing ConfigMap and restart the workload.'],
              },
            ],
          },
        ],
      },
    },
    ...overrides,
  };
}

describe('IngestionPreview', () => {
  it('shows the symptom → family chain, keywords, and confirmed remediation', () => {
    const markup = renderToStaticMarkup(<IngestionPreview candidate={candidate()} />);
    expect(markup).toContain('what activation writes');
    expect(markup).toContain('workload_startup_error');
    expect(markup).toContain('configmap missing at container start');
    expect(markup).toContain('createcontainerconfigerror');
    expect(markup).toContain('Recreate the missing ConfigMap');
  });

  it('warns loudly when the learned symptom has no remediation', () => {
    const noActions = candidate();
    noActions.payload!.compiled!.failure_modes![0].symptoms![0].actions = [];
    const markup = renderToStaticMarkup(<IngestionPreview candidate={noActions} />);
    expect(markup).toContain('matcher only');
    expect(markup).toContain('effective action');
  });

  it('renders nothing for a candidate without a compiled payload', () => {
    const bare = candidate({ payload: undefined });
    expect(renderToStaticMarkup(<IngestionPreview candidate={bare} />)).toBe('');
  });
});

describe('CandidateDetail', () => {
  const render = (item: KnowledgeCandidate) => renderToStaticMarkup(
    <CandidateDetail candidate={item} busy={false} onDecide={async () => {}} />,
  );

  it('leads with the family → symptom → action chain and hides backend identity', () => {
    const markup = render(candidate({
      root_cause_family: 'workload_startup_error',
      analysis_hash: '550d4ff6deadbeef',
      incident_id: 'INC-1',
      provenance: { source: 'approved_case_snapshot', case_id: 'ANL-1:550d4ff6deadbeef', promotion_path: 'harness_claim' },
    }));
    expect(markup).toContain('Family');
    expect(markup).toContain('Symptom (mechanism)');
    expect(markup).toContain('configmap missing at container start');
    expect(markup).toContain('Confirmed actions');
    expect(markup).toContain('Recreate the missing ConfigMap');
    // Reviewer-irrelevant plumbing stays out of the grid.
    expect(markup).not.toContain('Analysis hash');
    expect(markup).not.toContain('550d4ff6deadbeef');
    expect(markup).not.toContain('Case Id');
  });

  it('tells the reviewer how to record a missing action', () => {
    const noActions = candidate();
    noActions.payload!.compiled!.failure_modes![0].symptoms![0].actions = [];
    expect(render(noActions)).toContain('add the effective action in the evaluation review');
  });
});
