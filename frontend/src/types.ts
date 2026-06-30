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

export type SimilarIncident = {
  incident_id: string;
  alert_id?: string;
  title: string;
  severity: string;
  status: string;
  similarity: number;
  analysis_summary: string;
  analysis_detail?: string;
  positive_feedback: number;
  negative_feedback: number;
  comment_count: number;
  labels?: Record<string, string>;
  created_at: string;
};

export type FeedbackHint = {
  source_id: string;
  sentiment: string;
  weight: number;
  text: string;
};

export type CommentRecord = {
  comment_id: string;
  target_type: string;
  target_id: string;
  incident_id?: string;
  alert_id?: string;
  body: string;
  author?: string;
  created_at: string;
};

export type FeedbackSummary = {
  target_type: string;
  target_id: string;
  positive: number;
  negative: number;
  my_vote?: 'up' | 'down';
  comments: CommentRecord[];
  learning_hints?: FeedbackHint[];
};

export type AnalysisRun = {
  run_id: string;
  source: string;
  status: string;
  target_type: string;
  target_id: string;
  incident_id?: string;
  alert_id?: string;
  title: string;
  prompt?: string;
  analysis_summary: string;
  analysis_detail: string;
  analysis_quality: string;
  capabilities: Record<string, string>;
  missing_data: string[];
  warnings: string[];
  artifacts: Artifact[];
  created_at: string;
  updated_at: string;
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
  occurrence_count: number;
  occurrence_pods?: string[];
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
  similar_incidents: SimilarIncident[];
  feedback: FeedbackSummary;
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
  similar_incidents: SimilarIncident[];
  feedback: FeedbackSummary;
  alerts: AlertRecord[];
};

export type Envelope<T> = {
  status: string;
  data: T;
  pagination?: PageInfo;
};

export type PageInfo = {
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
};
