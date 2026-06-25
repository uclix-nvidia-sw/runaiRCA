import { AlertRecord, Envelope, Incident, IncidentDetail } from './types';

const runtimeApiBase = window.__RUNAI_RCA_CONFIG__?.apiBaseUrl;
const fallbackApiBase = import.meta.env.DEV ? 'http://localhost:8080' : '';
const API_BASE = (runtimeApiBase ?? import.meta.env.VITE_API_BASE_URL ?? fallbackApiBase).replace(/\/$/, '');

async function read<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

async function write<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export async function fetchIncidents(): Promise<Incident[]> {
  return (await read<Envelope<Incident[]>>('/api/v1/incidents')).data;
}

export async function fetchIncident(id: string): Promise<IncidentDetail> {
  return (await read<Envelope<IncidentDetail>>(`/api/v1/incidents/${encodeURIComponent(id)}`)).data;
}

export async function fetchAlerts(): Promise<AlertRecord[]> {
  return (await read<Envelope<AlertRecord[]>>('/api/v1/alerts')).data;
}

export async function fetchAlert(id: string): Promise<AlertRecord> {
  return (await read<Envelope<AlertRecord>>(`/api/v1/alerts/${encodeURIComponent(id)}`)).data;
}

export async function analyzeIncident(id: string): Promise<void> {
  await write(`/api/v1/incidents/${encodeURIComponent(id)}/analyze`);
}

export async function resolveIncident(id: string): Promise<void> {
  await write(`/api/v1/incidents/${encodeURIComponent(id)}/resolve`);
}

export async function chat(message: string, context: Record<string, unknown>) {
  return write<{ status: string; answer: string; conversation_id: string }>('/api/v1/chat', {
    message,
    context,
  });
}

export function eventSource(): EventSource {
  return new EventSource(`${API_BASE}/api/v1/events`);
}
