export type Artifact = {
  agent: string;
  source: string;
  type: string;
  status: string;
  confidence: string;
  query?: string;
  result?: unknown;
  summary?: string;
};

export type Incident = {
  incident_id: string;
  correlation_key: string;
  title: string;
  severity: string;
  status: string;
  fired_at: string;
  resolved_at?: string | null;
  alert_count: number;
  is_analyzing: boolean;
};

export type AlertRecord = {
  alert_id: string;
  incident_id: string;
  alarm_title: string;
  severity: string;
  status: string;
  fired_at: string;
  resolved_at?: string | null;
  fingerprint: string;
  thread_ts: string;
  labels: Record<string, string>;
  annotations: Record<string, string>;
  analysis_summary: string;
  analysis_detail: string;
  analysis_quality: string;
  capabilities: Record<string, string>;
  missing_data: string[];
  warnings: string[];
  artifacts: Artifact[];
  is_analyzing: boolean;
};

export type IncidentDetail = Incident & {
  analysis_summary: string;
  analysis_detail: string;
  analysis_quality: string;
  capabilities: Record<string, string>;
  missing_data: string[];
  warnings: string[];
  artifacts: Artifact[];
  alerts: AlertRecord[];
};

export type Envelope<T> = {
  status: string;
  data: T;
};
