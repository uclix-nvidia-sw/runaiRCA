import { AGENT_ORDER } from '../models/appTypes';
import type { Artifact } from '../types';

export type AgentTab = { agent: string; helpful: number; total: number; capability: string };

// Owner rule: a no-evidence check (e.g. a PASSING DB healthcheck) is not worth
// surfacing as a finding — count it, but keep it behind an expander.
const NO_EVIDENCE_PREFIX = '증거를 찾기 어렵습니다.';

export function isNoEvidenceArtifact(artifact: Artifact) {
  return String(artifact.summary || '').trim().startsWith(NO_EVIDENCE_PREFIX);
}

// Tabs = AGENT_ORDER + any agent present in artifacts but missing from it
// (e.g. "change"), in first-seen order. Default = first tab with real evidence.
export function agentTabs(artifacts: Artifact[], capabilities: Record<string, string>) {
  const extras = artifacts.map((a) => a.agent).filter((agent) => agent && !AGENT_ORDER.includes(agent));
  const order = [...AGENT_ORDER, ...Array.from(new Set(extras))];
  const tabs: AgentTab[] = order.map((agent) => {
    const own = artifacts.filter((a) => a.agent === agent);
    return {
      agent,
      helpful: own.filter((a) => !isNoEvidenceArtifact(a)).length,
      total: own.length,
      capability: capabilities[agent] || 'pending',
    };
  });
  return { tabs, defaultAgent: (tabs.find((t) => t.helpful > 0) || tabs[0]).agent };
}
