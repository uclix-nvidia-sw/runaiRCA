// Per-agent evidence rendering: the agent trail, one artifact's typed
// interpretation, and the raw query results behind it.
import { ChevronDown } from 'lucide-react';
import { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

import { type QueryDisplayItem } from '../../models/appTypes';
import { Artifact } from '../../types';
import { agentTabs, isNoEvidenceArtifact } from '../../utils/agentTrail';
import { artifactForPresentation } from '../../utils/artifactPresentation';
import {
  compactArtifactValue,
  formatArtifactValue,
  isEmptyResult,
  queryDisplayItems,
} from '../../utils/artifactValues';
import { evidenceMetadata, type EvidenceMetadata, type EvidenceWindow } from '../../utils/evidenceMetadata';
import { agentIcon, agentLabel, formatTime, formatTokenUsage } from '../../utils/formatters';
import { CopyableBlock } from '../common/UiParts';

export function AffectedPods({ pods }: { pods: string[] }) {
  if (!pods.length) return null;
  const shown = pods.slice(0, 12);
  const remaining = pods.length - shown.length;
  return (
    <div className="affected-pods">
      <span className="affected-pods-label">Affected pods · {pods.length}</span>
      <div className="affected-pods-list">
        {shown.map((pod) => (
          <code key={pod} className="pod-chip" title={pod}>{pod}</code>
        ))}
        {remaining > 0 && <span className="pod-chip pod-chip-more">+{remaining} more</span>}
      </div>
    </div>
  );
}


export function DiagnosticsPanel({ missingData, warnings, tokenUsage, analysisDuration }: { missingData: string[]; warnings: string[]; tokenUsage?: Record<string, unknown>; analysisDuration?: string }) {
  return (
    <section className="diagnostics">
      {analysisDuration && <div className="token-usage">Analysis time: {analysisDuration}</div>}
      {tokenUsage && <div className="token-usage">LLM tokens: {formatTokenUsage(tokenUsage)}</div>}
      {missingData.length > 0 && <DiagnosticGroup title="Missing Data" items={missingData} tone="missing" />}
      {warnings.length > 0 && <DiagnosticGroup title="Warnings" items={warnings} tone="warning" />}
    </section>
  );
}

function DiagnosticGroup({
  title,
  items,
  tone,
}: {
  title: string;
  items: string[];
  tone: 'missing' | 'warning';
}) {
  const [open, setOpen] = useState(false);
  const visibleItems = open ? items : items.slice(0, 3);
  const hiddenCount = Math.max(0, items.length - visibleItems.length);

  return (
    <div className={`diagnostic-group diagnostic-${tone}`}>
      <button className="diagnostic-toggle" onClick={() => setOpen((value) => !value)} type="button">
        <span>{title}</span>
        <strong>{items.length}</strong>
        <ChevronDown size={16} />
      </button>
      <ul>
        {visibleItems.map((item, index) => (
          <li key={`${title}-${index}-${item}`}>{item}</li>
        ))}
      </ul>
      {hiddenCount > 0 && (
        <button className="ghost-button compact-button diagnostic-more" onClick={() => setOpen(true)} type="button">
          <ChevronDown size={14} /> Show {hiddenCount} more
        </button>
      )}
    </div>
  );
}

// Surface WHY a collector is unavailable: match the aggregate missing-data keys and
// warnings back to this agent (keys are prefixed by source, e.g. "system_agent.url",
// "loki.auth", "runai.queue") so an Unavailable card explains itself.
function agentReasons(agent: string, missingData: string[], warnings: string[]): string[] {
  const needles = agent === 'system' ? ['system_agent', 'system'] : [agent];
  const hit = (s: string) => needles.some((n) => s.toLowerCase().includes(n));
  const friendly: Record<string, string> = {
    'system_agent.url': 'System agent is not configured (no URL) — node/kernel evidence was skipped.',
    'system_agent.node': 'No node is associated with this alert — node/kernel evidence was skipped.',
    'loki.auth': 'Loki authentication failed.',
  };
  const fromMissing = missingData.filter(hit).map((k) => friendly[k] || `missing: ${k}`);
  const fromWarnings = warnings.filter(hit);
  return Array.from(new Set([...fromMissing, ...fromWarnings]));
}

// Evidence trail: a collector tab strip (icon + label + helpful count + capability
// dot) over ONE full-width panel showing just the selected collector's artifacts.
// One card open at a time keeps the section scannable even at 100+ artifacts.
export function AgentTrail({
  artifacts,
  capabilities,
  missingData,
  warnings,
}: {
  artifacts: Artifact[];
  capabilities: Record<string, string>;
  missingData: string[];
  warnings: string[];
}) {
  const { tabs, defaultAgent } = agentTabs(artifacts, capabilities);
  // Lazy selection: until the user picks, follow the data-driven default so
  // artifacts arriving mid-analysis land on a useful tab.
  const [picked, setPicked] = useState<string | null>(null);
  const selected = picked !== null && tabs.some((tab) => tab.agent === picked) ? picked : defaultAgent;
  return (
    <>
      <div className="agent-tabs">
        {tabs.map((tab) => (
          <button
            key={tab.agent}
            className={`agent-tab ${tab.agent === selected ? 'active' : ''}`}
            onClick={() => setPicked(tab.agent)}
            type="button"
          >
            {agentIcon(tab.agent)}
            <strong>{agentLabel(tab.agent)}</strong>
            {tab.helpful > 0 && <span className="agent-tab-count">{tab.helpful}</span>}
            <span className={`agent-tab-dot capability-${tab.capability}`} aria-hidden />
          </button>
        ))}
      </div>
      <AgentEvidence
        key={selected}
        artifacts={artifacts.filter((artifact) => artifact.agent === selected)}
        reasons={agentReasons(selected, missingData, warnings)}
      />
    </>
  );
}

function AgentEvidence({ artifacts, reasons = [] }: { artifacts: Artifact[]; reasons?: string[] }) {
  const [showAll, setShowAll] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const emptyText = reasons.length > 0 ? reasons.join(' ') : 'No evidence yet.';
  const helpful = artifacts.filter((artifact) => !isNoEvidenceArtifact(artifact));
  const hidden = artifacts.length - helpful.length;
  const pool = showAll ? artifacts : helpful;
  const visible = expanded ? pool : pool.slice(0, 8);
  const more = pool.length - visible.length;
  return (
    <article className="agent-evidence">
      <div className="agent-content">
        {visible.length === 0 ? (
          <p className="empty">{emptyText}</p>
        ) : (
          visible.map((artifact, index) => (
            <ArtifactResult artifact={artifact} key={`${artifact.agent}-${artifact.type}-${index}`} />
          ))
        )}
        {more > 0 && (
          <button className="ghost-button compact-button artifact-more" onClick={() => setExpanded(true)} type="button">
            <ChevronDown size={14} /> Show {more} more
          </button>
        )}
        {hidden > 0 && (
          <button className="artifact-toggle compact-artifact-toggle" onClick={() => setShowAll((value) => !value)} type="button">
            {showAll ? `Hide ${hidden} no-evidence item(s)` : `Show ${hidden} no-evidence item(s)`}
          </button>
        )}
      </div>
    </article>
  );
}

function ArtifactResult({ artifact }: { artifact: Artifact }) {
  const [open, setOpen] = useState(false);
  const presented = artifactForPresentation(artifact);
  const queryItems = queryDisplayItems(presented.result);
  const resultText = presented.result !== undefined ? formatArtifactValue(compactArtifactValue(presented.result)) : '';
  const evidence = evidenceMetadata(artifact.result);
  // One-line summary so a collapsed row is scannable without expanding it.
  const preview = String(artifact.summary || '').split('\n')[0].replace(/[*`_#]/g, '').trim();
  return (
    <div className="artifact">
      <button className="artifact-toggle compact-artifact-toggle" onClick={() => setOpen((value) => !value)} type="button">
        <div className="artifact-head">
          <strong>{artifact.evidence_id ? `[${artifact.evidence_id}] ` : ''}{artifact.title || artifact.type}</strong>
          {!open && preview && <span className="artifact-preview">{preview}</span>}
          <span>{artifact.confidence}</span>
        </div>
        <ChevronDown size={16} />
      </button>
      {open && (
        <div className="artifact-body">
          {/* Emphasis (salient signals) is baked into the summary text as markdown
              bold by the backend, so it also survives Word export / raw JSON — render
              it as markdown instead of overlaying a frontend-only red highlight. */}
          <div className="artifact-summary">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{presented.summary ?? ''}</ReactMarkdown>
          </div>
          <EvidenceInterpretation evidence={evidence} />
          {queryItems.length > 0 ? (
            <QueryResultList items={queryItems} highlights={artifact.highlights} />
          ) : (
            <>
              {artifact.query && <CopyableBlock title="Query" value={artifact.query} kind="code" />}
              {presented.result !== undefined && !isEmptyResult(presented.result) && (
                <CopyableBlock
                  title="Result summary"
                  value={resultText}
                  kind="pre"
                  highlights={artifact.highlights}
                />
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function EvidenceInterpretation({
  evidence,
}: {
  evidence: ReturnType<typeof evidenceMetadata>;
}) {
  if (evidence === null) {
    return (
      <p className="evidence-limitation">
        이 아티팩트에는 형식화된 관측 메타데이터가 없습니다. 단독으로 인과관계를 확정하는 근거로 사용하지 마세요.
      </p>
    );
  }
  return (
    <section className="evidence-interpretation" aria-label="Evidence interpretation">
      <div className="evidence-interpretation-head">
        <strong>증거 해석</strong>
        <span className={evidence.typed ? 'evidence-typed' : 'evidence-untyped'}>
          {evidence.typed ? '형식화된 관측' : '불완전한 메타데이터'}
        </span>
      </div>
      <dl>
        <div>
          <dt>판정</dt>
          <dd>{evidencePolarityLabel(evidence.polarity)}</dd>
        </div>
        <div>
          <dt>범위</dt>
          <dd>{evidenceCoverageLabel(evidence.coverage)}</dd>
        </div>
        {evidence.entity && (
          <div className="evidence-interpretation-wide">
            <dt>관측 대상</dt>
            <dd>{evidence.entity}</dd>
          </div>
        )}
        {evidence.evidenceWindow && (
          <div className="evidence-interpretation-wide">
            <dt>신호 발생 시점</dt>
            <dd>{formatEvidenceWindow(evidence.evidenceWindow)}</dd>
          </div>
        )}
        {evidence.observationWindow && (
          <div className="evidence-interpretation-wide">
            <dt>조회 범위</dt>
            <dd>{formatEvidenceWindow(evidence.observationWindow)}</dd>
          </div>
        )}
      </dl>
      {!evidence.typed && (
        <p className="evidence-limitation">
          불완전한 관측 메타데이터는 진단 맥락일 뿐, 단독 인과 근거가 아닙니다.
        </p>
      )}
    </section>
  );
}

function formatEvidenceWindow(window: EvidenceWindow) {
  const start = formatTime(window.start);
  const end = formatTime(window.end);
  return start === end ? start : `${start} – ${end}`;
}

function evidencePolarityLabel(value: EvidenceMetadata['polarity']) {
  return {
    present: '신호 확인됨',
    absent: '신호 없음',
    unavailable: '조회 불가',
    unknown: '판정 불가',
  }[value || 'unknown'];
}

function evidenceCoverageLabel(value: EvidenceMetadata['coverage']) {
  return {
    scoped: '대상·시간 범위 확인됨',
    partial: '부분 범위',
    unknown: '범위 미확인',
  }[value || 'unknown'];
}

function QueryResultList({ items, highlights }: { items: QueryDisplayItem[]; highlights?: string[] }) {
  // A query that came back empty ([]/{}/blank) is noise — drop the whole card, not
  // just its result block, and don't flag it red. Its failure (if any) still shows
  // in the Warnings panel.
  const visible = items.filter((item) => !isEmptyResult(item.preview));
  if (visible.length === 0) return null;
  return (
    <div className="query-result-list">
      {visible.map((item) => (
        <QueryResultCard item={item} key={item.id} highlights={highlights} />
      ))}
    </div>
  );
}

function QueryResultCard({ item, highlights }: { item: QueryDisplayItem; highlights?: string[] }) {
  const previewText = item.preview === undefined ? '' : formatArtifactValue(item.preview);
  const [open, setOpen] = useState(false);
  return (
    <article className="query-result-card">
      <button className="query-result-toggle" onClick={() => setOpen((value) => !value)} type="button">
        <div className="query-result-head">
          <strong>{item.name}</strong>
          <span className={item.status === 'failed' ? 'query-status query-status-error' : 'query-status'}>{item.status}</span>
        </div>
        <ChevronDown size={16} />
      </button>
      {item.facts.length > 0 && (
        <div className="query-facts compact-query-facts">
          {item.facts.slice(0, open ? 4 : 2).map((fact) => (
            <span key={`${item.id}-${fact}`}>{fact}</span>
          ))}
        </div>
      )}
      {open && (
        <>
          {item.queryText && <CopyableBlock title={item.queryLabel} value={item.queryText} kind="code" />}
          {item.preview !== undefined && !isEmptyResult(item.preview) && (
            <CopyableBlock title="Relevant result" value={previewText} kind="pre" highlights={highlights} />
          )}
        </>
      )}
    </article>
  );
}

