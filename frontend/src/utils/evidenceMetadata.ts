export type EvidenceWindow = {
  start: string;
  end: string;
};

export type EvidenceMetadata = {
  polarity?: 'present' | 'absent' | 'unknown' | 'unavailable';
  coverage?: 'scoped' | 'partial' | 'unknown';
  entity?: string;
  observationWindow?: EvidenceWindow;
  evidenceWindow?: EvidenceWindow;
  typed: boolean;
};

const POLARITIES = new Set(['present', 'absent', 'unknown', 'unavailable']);
const COVERAGE = new Set(['scoped', 'partial', 'unknown']);

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function token(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const cleaned = value.trim().toLowerCase();
  return cleaned || undefined;
}

function text(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const cleaned = value.trim();
  return cleaned || undefined;
}

function window(value: unknown): EvidenceWindow | undefined {
  if (!isRecord(value)) return undefined;
  const start = text(value.start);
  const end = text(value.end);
  return start && end ? { start, end } : undefined;
}

/**
 * Read the collector's explicit observation envelope without inferring facts
 * from a successful HTTP response or a summary string. `evidence_window` is
 * when a positive signal actually occurred; `observation_window` is merely
 * the range the collector checked.
 */
export function evidenceMetadata(result: unknown): EvidenceMetadata | null {
  if (!isRecord(result) || !isRecord(result.observation)) return null;
  const observation = result.observation;
  const rawPolarity = token(observation.polarity);
  const rawCoverage = token(observation.coverage);
  const polarity = rawPolarity && POLARITIES.has(rawPolarity)
    ? rawPolarity as EvidenceMetadata['polarity']
    : undefined;
  const coverage = rawCoverage && COVERAGE.has(rawCoverage)
    ? rawCoverage as EvidenceMetadata['coverage']
    : undefined;
  return {
    polarity,
    coverage,
    entity: text(observation.observed_entity) || text(observation.entity),
    observationWindow: window(observation.observation_window) || window(observation.observed_window),
    evidenceWindow: window(observation.evidence_window),
    typed: Boolean(polarity && coverage),
  };
}
