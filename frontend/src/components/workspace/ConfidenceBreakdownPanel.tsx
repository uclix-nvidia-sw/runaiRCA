import { Gauge } from 'lucide-react';

type UnknownRecord = Record<string, unknown>;

export type ConfidenceScoreRow = {
  stage: string;
  label: string;
  effect: string;
  sourceGroups: string[];
};

export type ConfidenceGateRow = {
  label: string;
  detail: string;
  outcome: 'pass' | 'fail' | 'info';
};

export type ConfidenceBreakdownView = {
  hasRankingDetails: boolean;
  family?: string;
  rankingConfidence?: string;
  preHarnessFamily?: string;
  preHarnessConfidence?: string;
  finalFamily?: string;
  rankingScore?: number;
  finalConfidence?: string;
  independentSourceGroups: string[];
  scoreRows: ConfidenceScoreRow[];
  gateRows: ConfidenceGateRow[];
  selfCheck?: {
    before?: string;
    after?: string;
    refuted?: boolean;
    caveat?: string;
    nextCheck?: string;
  };
  harness?: {
    status?: string;
    overallScore?: number;
    before?: string;
    after?: string;
    hardGates: ConfidenceGateRow[];
  };
};

type ConfidenceBreakdownPanelProps = {
  diagnostics?: Record<string, unknown>;
  harness?: Record<string, unknown>;
  rootCauseFamily?: string;
};

const GATE_LABELS: Record<string, string> = {
  score_floor_passed: '최소 Ranking 점수',
  medium_score_passed: 'Medium 점수 기준',
  high_score_passed: 'High 점수 기준',
  independent_source_gate_passed: '독립 Source Group 기준',
  canonical_source_available: 'Canonical Source 사용 가능',
  unresolved_contradiction: '미해결 반증 없음',
  force_high: '강제 High 규칙',
  missing_evidence_trace: 'Evidence Trace 누락',
  invalid_evidence_link: 'Evidence Link 유효성',
  unsupported_high_confidence: 'High Confidence 근거',
  unresolved_contradiction_high_confidence: 'High Confidence 반증 해소',
  unsafe_action_without_guardrail: '위험 조치 Guardrail',
};

function record(value: unknown): UnknownRecord | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as UnknownRecord;
}

function stringValue(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function booleanValue(value: unknown): boolean | undefined {
  return typeof value === 'boolean' ? value : undefined;
}

function strings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return Array.from(new Set(value.map(stringValue).filter((item): item is string => Boolean(item))));
}

function humanize(value: string): string {
  return value
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function formatNumber(value: number): string {
  return Number.isInteger(value) ? String(value) : value.toFixed(2).replace(/0+$/, '').replace(/\.$/, '');
}

function scoreEffect(item: UnknownRecord): string {
  const delta = numberValue(item.delta);
  if (delta !== undefined) return `${delta >= 0 ? '+' : ''}${formatNumber(delta)}`;
  const floor = numberValue(item.score_floor);
  if (floor !== undefined) return `최소 ${formatNumber(floor)}점`;
  const factor = numberValue(item.factor);
  if (factor !== undefined) return `×${formatNumber(factor)}`;
  return '—';
}

function parseScoreRows(candidate: UnknownRecord | undefined): ConfidenceScoreRow[] {
  const breakdown = candidate?.score_breakdown;
  if (!Array.isArray(breakdown)) return [];
  return breakdown.flatMap((value) => {
    const item = record(value);
    if (!item) return [];
    const stage = stringValue(item.stage) || stringValue(item.kind) || 'ranking';
    const label = stringValue(item.label) || stringValue(item.kind) || '점수 조정';
    const sourceGroups = strings(item.source_groups);
    const singleSource = stringValue(item.source_group);
    if (singleSource && !sourceGroups.includes(singleSource)) sourceGroups.push(singleSource);
    return [{ stage, label, effect: scoreEffect(item), sourceGroups }];
  });
}

function gateDetail(candidate: UnknownRecord, key: string): string {
  if (key === 'score_floor_passed') {
    const threshold = numberValue(candidate.score_floor);
    return threshold === undefined ? '' : `${formatNumber(threshold)}점 이상`;
  }
  if (key === 'medium_score_passed') {
    const threshold = numberValue(candidate.medium_score_threshold);
    return threshold === undefined ? '' : `${formatNumber(threshold)}점 이상`;
  }
  if (key === 'high_score_passed') {
    const threshold = numberValue(candidate.high_score_threshold);
    return threshold === undefined ? '' : `${formatNumber(threshold)}점 이상`;
  }
  if (key === 'independent_source_gate_passed') {
    const required = numberValue(candidate.required_independent_source_groups);
    const observed = strings(candidate.independent_source_groups).length;
    return required === undefined ? `${observed}개 관측` : `${observed}/${formatNumber(required)}개`;
  }
  if (key === 'canonical_source_available') {
    return stringValue(candidate.canonical_source) || '';
  }
  return '';
}

function parseConfidenceGates(candidate: UnknownRecord | undefined): ConfidenceGateRow[] {
  if (!candidate) return [];
  const orderedKeys = [
    'score_floor_passed',
    'medium_score_passed',
    'high_score_passed',
    'independent_source_gate_passed',
    'canonical_source_available',
    'unresolved_contradiction',
    'force_high',
  ];
  const rows: ConfidenceGateRow[] = [];
  for (const key of orderedKeys) {
    const value = booleanValue(candidate[key]);
    if (value === undefined) continue;
    if (key === 'force_high') {
      rows.push({
        label: GATE_LABELS[key],
        detail: value ? '적용됨' : '미적용',
        outcome: 'info',
      });
      continue;
    }
    const passed = key === 'unresolved_contradiction' ? !value : value;
    rows.push({
      label: GATE_LABELS[key] || humanize(key),
      detail: gateDetail(candidate, key),
      outcome: passed ? 'pass' : 'fail',
    });
  }
  return rows;
}

function parseHardGates(value: unknown): ConfidenceGateRow[] {
  const gates = record(value);
  if (!gates) return [];
  return Object.entries(gates).flatMap(([key, raw]) => {
    const triggered = booleanValue(raw);
    if (triggered === undefined) return [];
    return [{
      label: GATE_LABELS[key] || humanize(key),
      detail: triggered ? '위반 감지' : '위반 없음',
      outcome: triggered ? 'fail' as const : 'pass' as const,
    }];
  });
}

function parseSelfCheck(value: unknown): ConfidenceBreakdownView['selfCheck'] {
  const item = record(value);
  if (!item) return undefined;
  const result = {
    before: stringValue(item.confidence_before),
    after: stringValue(item.confidence_after),
    refuted: booleanValue(item.refuted),
    caveat: stringValue(item.caveat),
    nextCheck: stringValue(item.next_check),
  };
  return Object.values(result).some((entry) => entry !== undefined) ? result : undefined;
}

function parseHarness(primary: unknown, fallback: unknown): ConfidenceBreakdownView['harness'] {
  const preferred = record(primary);
  const legacy = record(fallback);
  if (!preferred && !legacy) return undefined;
  const status = stringValue(preferred?.status) || stringValue(legacy?.status);
  const overallScore = numberValue(preferred?.overall_score) ?? numberValue(legacy?.overall_score);
  const before = stringValue(preferred?.confidence_before) || stringValue(legacy?.confidence_before);
  const after = stringValue(preferred?.confidence_after) || stringValue(legacy?.confidence_after);
  const hardGates = parseHardGates(preferred?.hard_gates ?? legacy?.hard_gates);
  if (!status && overallScore === undefined && !before && !after && hardGates.length === 0) return undefined;
  return { status, overallScore, before, after, hardGates };
}

export function parseConfidenceBreakdown(
  diagnostics?: Record<string, unknown>,
  harness?: Record<string, unknown>,
  rootCauseFamily?: string,
): ConfidenceBreakdownView | null {
  const source = record(diagnostics);
  const rankingCandidate = record(source?.ranking_candidate);
  const preHarnessCandidate = record(source?.pre_harness_candidate);
  const finalCandidate = record(source?.final_candidate);
  const parsedHarness = parseHarness(source?.harness, harness);
  const hasRankingDetails = Boolean(rankingCandidate);
  if (!hasRankingDetails && !parsedHarness) return null;

  return {
    hasRankingDetails,
    family: stringValue(rankingCandidate?.family) || stringValue(rootCauseFamily),
    rankingConfidence: stringValue(rankingCandidate?.confidence),
    preHarnessFamily: stringValue(preHarnessCandidate?.family),
    preHarnessConfidence: stringValue(preHarnessCandidate?.confidence),
    finalFamily: stringValue(finalCandidate?.family),
    rankingScore: numberValue(rankingCandidate?.score),
    finalConfidence: stringValue(finalCandidate?.confidence) || stringValue(rankingCandidate?.confidence),
    independentSourceGroups: strings(rankingCandidate?.independent_source_groups),
    scoreRows: parseScoreRows(rankingCandidate),
    gateRows: parseConfidenceGates(record(rankingCandidate?.confidence_gate)),
    selfCheck: parseSelfCheck(source?.self_check),
    harness: parsedHarness,
  };
}

function OutcomeBadge({ outcome }: { outcome: ConfidenceGateRow['outcome'] }) {
  const label = outcome === 'pass' ? '통과' : outcome === 'fail' ? '실패' : '정보';
  return <span className={`confidence-outcome confidence-outcome-${outcome}`}>{label}</span>;
}

function GateTable({ rows, label }: { rows: ConfidenceGateRow[]; label: string }) {
  if (rows.length === 0) return <p className="confidence-empty">기록된 gate 정보가 없습니다.</p>;
  return (
    <div className="confidence-table-scroll" role="region" aria-label={label} tabIndex={0}>
      <table className="confidence-table">
        <caption className="sr-only">{label}</caption>
        <thead><tr><th scope="col">검증 기준</th><th scope="col">기준/관측</th><th scope="col">결과</th></tr></thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={`${row.label}-${index}`}>
              <th scope="row">{row.label}</th>
              <td>{row.detail || '—'}</td>
              <td><OutcomeBadge outcome={row.outcome} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ConfidenceBreakdownPanel({
  diagnostics,
  harness,
  rootCauseFamily,
}: ConfidenceBreakdownPanelProps) {
  const view = parseConfidenceBreakdown(diagnostics, harness, rootCauseFamily);
  if (!view) return null;

  const confidenceTransition = [view.selfCheck?.before, view.selfCheck?.after].filter(Boolean).join(' → ');
  const harnessTransition = [view.harness?.before, view.harness?.after].filter(Boolean).join(' → ');

  return (
    <section className="feedback-panel confidence-breakdown-panel" aria-labelledby="confidence-breakdown-title">
      <div className="section-title" id="confidence-breakdown-title"><Gauge size={18} /> Confidence 산정 근거</div>

      {!view.hasRankingDetails ? (
        <>
          <p className="confidence-legacy-note">
            이 분석 run에는 세부 ranking 진단이 기록되지 않았습니다. 아래 값은 기존 run에 남아 있는 Harness 품질 평가이며, ranking 점수나 evidence 가중치를 추정하지 않습니다.
          </p>
          <div className="confidence-summary confidence-summary-legacy" aria-label="기존 run Harness 요약">
            <p><strong>Harness 상태</strong><span>{view.harness?.status || '—'}</span></p>
            <p><strong>Harness 품질 점수</strong><span>{view.harness?.overallScore === undefined ? '—' : `${formatNumber(view.harness.overallScore)}/100`}</span></p>
          </div>
          {view.harness && <GateTable rows={view.harness.hardGates} label="Harness hard gate 결과" />}
        </>
      ) : (
        <>
          <div className="confidence-system-note">
            <p><strong>결정론적 Ranking</strong><span>수집 evidence와 규칙으로 후보 순서를 계산합니다. 이 점수는 확률이 아닙니다.</span></p>
            <p><strong>Harness 품질 평가</strong><span>최종 보고서의 근거성·안전성을 별도 0–100점으로 검사합니다. Ranking 점수와 합산하지 않습니다.</span></p>
          </div>

          <div className="confidence-summary" aria-label="Confidence 요약">
            <p><strong>후보 Family</strong><span>{view.family || '—'}</span></p>
            <p><strong>Ranking 점수</strong><span>{view.rankingScore === undefined ? '—' : formatNumber(view.rankingScore)}</span></p>
            <p><strong>Ranking Confidence</strong><span>{view.rankingConfidence || '—'}</span></p>
            <p><strong>독립 Source Group</strong><span>{view.independentSourceGroups.length ? view.independentSourceGroups.join(', ') : '기록 없음'}</span></p>
          </div>

          {(view.preHarnessFamily || view.finalFamily || view.finalConfidence) && (
            <p className="confidence-final-note">
              Harness 직전: <strong>{view.preHarnessFamily || view.family || '—'} / {view.preHarnessConfidence || '—'}</strong>
              {' · '}최종 선택: <strong>{view.finalFamily || view.preHarnessFamily || view.family || '—'} / {view.finalConfidence || '—'}</strong>
            </p>
          )}

          <div className="confidence-subsection">
            <h3>Ranking 점수 내역</h3>
            {view.scoreRows.length ? (
              <div className="confidence-table-scroll" role="region" aria-label="Ranking 점수 내역" tabIndex={0}>
                <table className="confidence-table confidence-score-table">
                  <caption className="sr-only">결정론적 ranking 점수의 단계별 증감</caption>
                  <thead><tr><th scope="col">단계</th><th scope="col">근거/규칙</th><th scope="col">점수 효과</th><th scope="col">Source Group</th></tr></thead>
                  <tbody>
                    {view.scoreRows.map((row, index) => (
                      <tr key={`${row.stage}-${row.label}-${index}`}>
                        <td><span className="confidence-stage">{humanize(row.stage)}</span></td>
                        <th scope="row">{row.label}</th>
                        <td className="confidence-delta">{row.effect}</td>
                        <td>{row.sourceGroups.length ? row.sourceGroups.join(', ') : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : <p className="confidence-empty">이 후보에는 세부 점수 증감 내역이 기록되지 않았습니다.</p>}
          </div>

          <div className="confidence-subsection">
            <h3>Confidence Gate</h3>
            <GateTable rows={view.gateRows} label="Ranking confidence gate 결과" />
          </div>

          {view.selfCheck && (
            <div className="confidence-subsection">
              <h3>Self-Check</h3>
              <dl className="confidence-detail-grid">
                <div><dt>Confidence 변화</dt><dd>{confidenceTransition || '변화 기록 없음'}</dd></div>
                <div><dt>반증 판정</dt><dd>{view.selfCheck.refuted === undefined ? '기록 없음' : view.selfCheck.refuted ? '반증됨' : '반증되지 않음'}</dd></div>
                <div className="confidence-detail-wide"><dt>Caveat</dt><dd>{view.selfCheck.caveat || '기록 없음'}</dd></div>
                <div className="confidence-detail-wide"><dt>다음 확인</dt><dd>{view.selfCheck.nextCheck || '기록 없음'}</dd></div>
              </dl>
            </div>
          )}

          {view.harness && (
            <div className="confidence-subsection confidence-harness-section">
              <h3>Harness 품질 평가 <span>Ranking과 별도</span></h3>
              <div className="confidence-summary" aria-label="Harness 요약">
                <p><strong>상태</strong><span>{view.harness.status || '—'}</span></p>
                <p><strong>품질 점수</strong><span>{view.harness.overallScore === undefined ? '—' : `${formatNumber(view.harness.overallScore)}/100`}</span></p>
                <p><strong>Confidence 조정</strong><span>{harnessTransition || '조정 기록 없음'}</span></p>
              </div>
              <GateTable rows={view.harness.hardGates} label="Harness hard gate 결과" />
            </div>
          )}
        </>
      )}
    </section>
  );
}
