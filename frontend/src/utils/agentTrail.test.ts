import { describe, expect, it } from 'vitest';

import { agentTabs } from './agentTrail';
import type { Artifact } from '../types';

const art = (agent: string, summary = 'found something'): Artifact =>
  ({ agent, source: agent, type: 't', status: 'ok', confidence: 'high', summary } as Artifact);

describe('agentTabs', () => {
  it('appends unknown agents (change) after AGENT_ORDER with helpful/total counts', () => {
    const { tabs } = agentTabs(
      [art('kubernetes'), art('change'), art('change', '증거를 찾기 어렵습니다. nothing'), art('change')],
      { kubernetes: 'ok' },
    );
    expect(tabs.map((t) => t.agent)).toEqual([
      'runai', 'kubernetes', 'postgres', 'prometheus', 'loki', 'system', 'change',
    ]);
    expect(tabs.find((t) => t.agent === 'change')).toMatchObject({ helpful: 2, total: 3, capability: 'pending' });
    expect(tabs.find((t) => t.agent === 'kubernetes')).toMatchObject({ helpful: 1, capability: 'ok' });
  });

  it('defaults to the first tab with real evidence, else the first tab', () => {
    expect(agentTabs([art('runai', '증거를 찾기 어렵습니다. skip'), art('prometheus')], {}).defaultAgent).toBe('prometheus');
    expect(agentTabs([], {}).defaultAgent).toBe('runai');
  });
});
