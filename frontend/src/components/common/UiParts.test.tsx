import { describe, expect, it } from 'vitest';

import { highlightSegments } from './UiParts';

describe('highlightSegments', () => {
  it('does not infer problem signals from raw Kubernetes values', () => {
    const text = JSON.stringify({
      preemptionPolicy: 'PreemptLowerPriority',
      conditions: [{ type: 'PodScheduled', status: 'True', reason: 'Unschedulable' }],
    });

    expect(highlightSegments(text)).toEqual([text]);
  });

  it('renders only complete backend-verified markers', () => {
    const policy = 'PreemptLowerPriority';
    expect(highlightSegments(policy, ['Preempt'])).toEqual([policy]);

    const observed = 'Warning: pod was Preempted by scheduler';
    expect(highlightSegments(observed, ['Preempted'])).toHaveLength(3);
  });
});
