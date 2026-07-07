import { AlertRecord, AnalysisRun, Envelope, FeedbackSummary, Incident, IncidentDetail, KPIStats, LLMSpendStats, PageInfo, RecurrenceStats } from './types';

const runtimeApiBase = window.__RUNAI_RCA_CONFIG__?.apiBaseUrl;
const fallbackApiBase = import.meta.env.DEV ? 'http://localhost:8080' : '';
const configuredApiBase = normalizeApiBase(runtimeApiBase) ?? normalizeApiBase(import.meta.env.VITE_API_BASE_URL);
const API_BASE = configuredApiBase ?? fallbackApiBase;
const FEEDBACK_ACTOR_KEY = 'runai-rca-feedback-actor';
const MAX_ERROR_BODY_BYTES = 4096;

export type FeedbackVote = 'up' | 'down' | 'none';
export type PageRequest = { limit: number; offset: number };
export type PageResult<T> = { items: T[]; page: PageInfo };
export type IncidentView = 'active' | 'archived' | 'trash';
export type IncidentFilters = {
  status?: string;
  severity?: string;
  finalDecision?: string;
};
export type AlertFilters = {
  status?: string;
  severity?: string;
};

async function read<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    throw new Error(await responseErrorMessage(response));
  }
  return response.json() as Promise<T>;
}

async function write<T>(path: string, body?: unknown): Promise<T> {
  return mutate<T>('POST', path, body);
}

async function mutate<T>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(await responseErrorMessage(response));
  }
  return response.json() as Promise<T>;
}

export async function fetchIncidents(page?: PageRequest, view: IncidentView = 'active', filters: IncidentFilters = {}): Promise<PageResult<Incident>> {
  const response = await read<Envelope<Incident[]>>(
    `/api/v1/incidents${pageQuery(page, {
      view,
      status: filters.status,
      severity: filters.severity,
      final_decision: filters.finalDecision,
    })}`,
  );
  return pageResult(response, page);
}

export async function fetchIncident(id: string): Promise<IncidentDetail> {
  return (
    await read<Envelope<IncidentDetail>>(
      `/api/v1/incidents/${encodeURIComponent(id)}${feedbackActorQuery()}`,
    )
  ).data;
}

export async function fetchAlerts(page?: PageRequest, filters: AlertFilters = {}): Promise<PageResult<AlertRecord>> {
  const response = await read<Envelope<AlertRecord[]>>(
    `/api/v1/alerts${pageQuery(page, {
      status: filters.status,
      severity: filters.severity,
    })}`,
  );
  return pageResult(response, page);
}

export async function fetchAnalysisRuns(page?: PageRequest): Promise<PageResult<AnalysisRun>> {
  const response = await read<Envelope<AnalysisRun[]>>(`/api/v1/analysis-runs${pageQuery(page)}`);
  return pageResult(response, page);
}

export async function fetchAlert(id: string): Promise<AlertRecord> {
  return (
    await read<Envelope<AlertRecord>>(`/api/v1/alerts/${encodeURIComponent(id)}${feedbackActorQuery()}`)
  ).data;
}

export async function analyzeIncident(id: string): Promise<void> {
  await write(`/api/v1/incidents/${encodeURIComponent(id)}/analyze`);
}

export async function resolveIncident(id: string): Promise<void> {
  await write(`/api/v1/incidents/${encodeURIComponent(id)}/resolve`);
}

export async function archiveIncident(id: string): Promise<void> {
  await write(`/api/v1/incidents/${encodeURIComponent(id)}/archive`);
}

export async function unarchiveIncident(id: string): Promise<void> {
  await write(`/api/v1/incidents/${encodeURIComponent(id)}/unarchive`);
}

export async function restoreIncident(id: string): Promise<void> {
  await write(`/api/v1/incidents/${encodeURIComponent(id)}/restore`);
}

export async function deleteIncident(id: string, permanent = false): Promise<void> {
  const suffix = permanent ? '?permanent=true' : '';
  await mutate('DELETE', `/api/v1/incidents/${encodeURIComponent(id)}${suffix}`);
}

export async function fetchRecurrenceStats(days = 7): Promise<RecurrenceStats> {
  return (await read<Envelope<RecurrenceStats>>(`/api/v1/stats/recurrence?days=${encodeURIComponent(String(days))}`)).data;
}

export async function fetchLLMSpendStats(days = 7): Promise<LLMSpendStats> {
  return (await read<Envelope<LLMSpendStats>>(`/api/v1/stats/llm-spend?days=${encodeURIComponent(String(days))}`)).data;
}

export async function fetchKPIStats(days = 7): Promise<KPIStats> {
  return (await read<Envelope<KPIStats>>(`/api/v1/stats/kpi?days=${encodeURIComponent(String(days))}`)).data;
}

export async function submitFeedback(
  targetType: 'incident' | 'alert',
  id: string,
  vote: FeedbackVote,
): Promise<FeedbackSummary> {
  const path = targetPath(targetType, id, 'vote');
  return (await write<Envelope<FeedbackSummary>>(path, { vote_type: vote, author: feedbackActorID() })).data;
}

export async function addComment(
  targetType: 'incident' | 'alert',
  id: string,
  body: string,
): Promise<FeedbackSummary> {
  const path = targetPath(targetType, id, 'comments');
  return (await write<Envelope<FeedbackSummary>>(path, { body })).data;
}

export async function updateComment(
  targetType: 'incident' | 'alert',
  id: string,
  commentID: string,
  body: string,
): Promise<FeedbackSummary> {
  const path = `${targetPath(targetType, id, 'comments')}/${encodeURIComponent(commentID)}`;
  return (await mutate<Envelope<FeedbackSummary>>('PUT', path, { body })).data;
}

export async function deleteComment(
  targetType: 'incident' | 'alert',
  id: string,
  commentID: string,
): Promise<FeedbackSummary> {
  const path = `${targetPath(targetType, id, 'comments')}/${encodeURIComponent(commentID)}`;
  return (await mutate<Envelope<FeedbackSummary>>('DELETE', path)).data;
}

export type ChatRequest = {
  message: string;
  conversation_id?: string;
  language?: 'ko' | 'en';
  page?: string;
  auto?: boolean;
  incident_id?: string;
  alert_id?: string;
  incident_title?: string;
  incident_content?: string;
  alert_title?: string;
  alert_content?: string;
  context?: Record<string, unknown>;
};

export type ChatResponse = {
  status: string;
  answer: string;
  message?: string;
  response?: string;
  conversation_id: string;
  analysis_run?: AnalysisRun;
};

export async function chat(payload: ChatRequest) {
  return write<ChatResponse>('/api/v1/chat', payload);
}

export function eventSource(): EventSource {
  return new EventSource(`${API_BASE}/api/v1/events`);
}

function nonEmpty(value: unknown) {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed === '' ? undefined : trimmed;
}

function normalizeApiBase(value: unknown) {
  const trimmed = nonEmpty(value);
  if (!trimmed) return undefined;
  const withoutTrailingSlash = trimmed.replace(/\/$/, '');
  if (withoutTrailingSlash.startsWith('/')) return withoutTrailingSlash;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(withoutTrailingSlash)) return withoutTrailingSlash;
  if (
    withoutTrailingSlash.startsWith('localhost') ||
    withoutTrailingSlash.startsWith('127.') ||
    withoutTrailingSlash.startsWith('[') ||
    withoutTrailingSlash.includes('.')
  ) {
    return `http://${withoutTrailingSlash}`;
  }
  return `/${withoutTrailingSlash.replace(/^\/+/, '')}`;
}

function targetPath(targetType: 'incident' | 'alert', id: string, action: string) {
  const collection = targetType === 'incident' ? 'incidents' : 'alerts';
  return `/api/v1/${collection}/${encodeURIComponent(id)}/${action}`;
}

function pageQuery(page?: PageRequest, extra?: Record<string, string | undefined>) {
  const params = new URLSearchParams();
  if (page) {
    params.set('limit', String(page.limit));
    params.set('offset', String(page.offset));
  }
  for (const [key, value] of Object.entries(extra ?? {})) {
    if (!value) continue;
    params.set(key, value);
  }
  const query = params.toString();
  return query ? `?${query}` : '';
}

function pageResult<T>(response: Envelope<T[]>, requested?: PageRequest): PageResult<T> {
  const fallbackLimit = requested?.limit ?? response.data.length;
  const fallbackOffset = requested?.offset ?? 0;
  return {
    items: response.data,
    page: response.pagination ?? {
      total: response.data.length,
      limit: fallbackLimit,
      offset: fallbackOffset,
      has_more: fallbackOffset + fallbackLimit < response.data.length,
    },
  };
}

function feedbackActorQuery() {
  return `?feedback_author=${encodeURIComponent(feedbackActorID())}`;
}

async function responseErrorMessage(response: Response) {
  const fallback = `Request failed: ${response.status}`;
  const contentType = response.headers.get('content-type') || '';
  try {
    const { text, truncated } = await readLimitedResponseText(response, MAX_ERROR_BODY_BYTES);
    const bodyText = text.trim();
    if (!bodyText) return fallback;
    if (contentType.includes('application/json')) {
      if (truncated) return `${fallback}: response body exceeded ${MAX_ERROR_BODY_BYTES} bytes`;
      const body = JSON.parse(bodyText) as { error?: unknown; message?: unknown; status?: unknown };
      return stringField(body.error) || stringField(body.message) || stringField(body.status) || fallback;
    }
    return truncated ? `${bodyText}...` : bodyText;
  } catch {
    return fallback;
  }
}

async function readLimitedResponseText(response: Response, limit: number) {
  if (!response.body) {
    const text = await response.text();
    return { text: text.slice(0, limit), truncated: text.length > limit };
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let text = '';
  let truncated = false;
  let bytesRead = 0;
  try {
    while (bytesRead < limit) {
      const { done, value } = await reader.read();
      if (done) break;
      const remaining = limit - bytesRead;
      if (value.byteLength > remaining) {
        text += decoder.decode(value.slice(0, remaining), { stream: true });
        truncated = true;
        await reader.cancel();
        break;
      }
      bytesRead += value.byteLength;
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
  } finally {
    reader.releaseLock();
  }

  return { text, truncated };
}

function stringField(value: unknown) {
  return typeof value === 'string' && value.trim() ? value : undefined;
}

function feedbackActorID() {
  try {
    const existing = window.localStorage.getItem(FEEDBACK_ACTOR_KEY);
    if (existing) {
      return existing;
    }
    const random =
      typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
        ? crypto.randomUUID()
        : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const actor = `browser-${random}`;
    window.localStorage.setItem(FEEDBACK_ACTOR_KEY, actor);
    return actor;
  } catch {
    return 'browser-anonymous';
  }
}
