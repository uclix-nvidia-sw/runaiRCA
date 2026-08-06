// Value-shaping helpers shared by the RCA workspace: they turn arbitrary
// collector payloads into something renderable without ever throwing.
import { type QueryDisplayItem } from '../models/appTypes';

// The report's "## 3. 권장 조치 (Recommended Actions)" numbered items, one per
// line, for seeding the correction form. First line of each item only — the
// operator is editing, not archiving.
export function reportActionLines(markdown: string): string {
  const start = markdown.search(/^## 3\./m);
  if (start < 0) return '';
  const section = markdown.slice(start);
  const next = section.slice(6).search(/^## /m);
  const body = next < 0 ? section : section.slice(0, next + 6);
  return body
    .split('\n')
    .map((line) => /^\s*\d+\.\s+(.*)$/.exec(line)?.[1] ?? '')
    .filter(Boolean)
    .join('\n');
}

export function errorMessage(err: unknown, fallback: string) {
  return err instanceof Error ? err.message : fallback;
}

export function formatArtifactValue(value: unknown) {
  return typeof value === 'string' ? value : safeJSONStringify(value, 2);
}

export function safeJSONStringify(value: unknown, space?: number) {
  const seen = new WeakSet<object>();
  try {
    const serialized = JSON.stringify(
      value,
      (_key, item) => {
        if (typeof item !== 'object' || item === null) {
          return item;
        }
        if (seen.has(item)) {
          return '[Circular]';
        }
        seen.add(item);
        return item;
      },
      space,
    );
    return serialized ?? String(value);
  } catch (err) {
    return `[Unserializable: ${errorMessage(err, 'unknown value')}]`;
  }
}

export function compactArtifactValue(value: unknown, depth = 3): unknown {
  if (depth <= 0) {
    if (Array.isArray(value)) return `[${value.length} item(s)]`;
    if (isPlainObject(value)) return '{...}';
    return value;
  }
  if (Array.isArray(value)) {
    const trimmed = value.slice(0, 4).map((item) => compactArtifactValue(item, depth - 1));
    if (value.length > 4) {
      trimmed.push({ truncated: value.length - 4 });
    }
    return trimmed;
  }
  if (!isPlainObject(value)) return value;

  const priorityKeys = [
    'name',
    'namespace',
    'path',
    'query',
    'status',
    'status_code',
    'error',
    'reason',
    'message',
    'phase',
    'nodeName',
    'ready',
    'restartCount',
    'line_count',
    'stream_count',
    'items',
    'conditions',
    'containerStatuses',
    'data',
    'sample',
  ];
  const keys = Object.keys(value);
  const selected = [
    ...priorityKeys.filter((key) => key in value),
    ...keys.filter((key) => !priorityKeys.includes(key)),
  ].slice(0, 9);

  const compacted: Record<string, unknown> = {};
  for (const key of selected) {
    compacted[key] = compactArtifactValue(value[key], depth - 1);
  }
  if (keys.length > selected.length) {
    compacted.truncated_keys = keys.length - selected.length;
  }
  return compacted;
}

export function queryDisplayItems(result: unknown): QueryDisplayItem[] {
  if (!isPlainObject(result) || !Array.isArray(result.queries)) return [];
  return result.queries
    .filter(isPlainObject)
    .map((query, index) => {
      const name = stringValue(query.name) || `query_${index + 1}`;
      const statusCode = numberValue(query.status_code);
      const error = stringValue(query.error);
      const rawStatus = stringValue(query.status);
      // Collectors that pre-extract the salient content (e.g. Loki's flat
      // sample_lines: the actual log text) win over the nested sample/data,
      // which compactArtifactValue would otherwise crush to "[N item(s)]".
      const sampleLines = Array.isArray(query.sample_lines) ? (query.sample_lines as unknown[]) : undefined;
      const previewSource = query.sample !== undefined ? query.sample : query.data;
      // A query failed if the transport 4xx/5xx'd OR the response BODY reports an
      // error. MCP builders stamp a fixed status_code:200/error:None and hide the
      // real failure in the body — runai as a numeric {status:404,…}, Prometheus/
      // Loki as a "error" status. Any of these must render red, not a green pill.
      const bodyStatus = isPlainObject(previewSource) ? numberValue(previewSource.status) : undefined;
      const failed =
        Boolean(error) ||
        (statusCode !== undefined && statusCode >= 400) ||
        (bodyStatus !== undefined && bodyStatus >= 400) ||
        rawStatus === 'error';
      const status = failed ? 'failed' : rawStatus || (statusCode ? String(statusCode) : 'ok');
      const queryText = stringValue(query.query) || stringValue(query.path) || stringValue(query.url) || '';
      const facts = [
        statusCode ? `HTTP ${statusCode}` : '',
        numberValue(query.stream_count) !== undefined ? `${numberValue(query.stream_count)} stream(s)` : '',
        numberValue(query.line_count) !== undefined ? `${numberValue(query.line_count)} line(s)` : '',
        error ? error : '',
      ].filter(Boolean);
      return {
        id: `${name}-${index}`,
        name: humanizeKey(name),
        queryText,
        queryLabel: query.query ? 'Query' : query.path ? 'Path' : 'URL',
        status,
        statusCode,
        error,
        facts,
        preview: sampleLines ?? (previewSource === undefined ? undefined : compactArtifactValue(previewSource)),
      };
    });
}

function stringValue(value: unknown) {
  return typeof value === 'string' ? value : '';
}

function numberValue(value: unknown) {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

// Empty results ([], {}, "") are noise — collectors that ran and found nothing
// still show their status/facts, just not a barren "Relevant result: []".
export function isEmptyResult(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  if (Array.isArray(value)) return value.length === 0;
  if (isPlainObject(value)) return Object.keys(value).length === 0;
  if (typeof value === 'string') return value.trim() === '';
  return false;
}

function humanizeKey(value: string) {
  return value.replace(/[_:]/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}

