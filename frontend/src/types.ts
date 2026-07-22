export type Artifact = {
  evidence_id?: string;
  agent: string;
  source: string;
  type: string;
  status: string;
  confidence: string;
  query?: string;
  result?: unknown;
  summary?: string;
  /** Human-facing card title (e.g. "파드 조회"); fall back to `type`. */
  title?: string;
  /** Problem signals extracted from `result`; rendered in red. */
  highlights?: string[];
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

export type EvaluationReview = {
  review_id: string;
  run_id: string;
  analysis_hash: string;
  reviewer: string;
  case_type: 'known' | 'compositional' | 'novel' | 'tool_degraded';
  expected_family?: string;
  scores: Record<string, number>;
  hard_gates: Record<string, boolean>;
  resolution_outcome: 'resolved' | 'mitigated' | 'ineffective' | 'unknown';
  effective_action?: string;
  notes?: string;
  operator_confirmed?: boolean;
  created_at: string;
  updated_at: string;
};

export type KnowledgePromotionPreview = {
  outcome: 'ready' | 'validation_failed' | 'blocked' | 'not_approved';
  reason?: string;
  family?: string;
  evidence_count: number;
  probe_count: number;
  candidate_id?: string;
};

export type EvaluationView = {
  run_id: string;
  analysis_hash: string;
  harness?: Record<string, unknown>;
  my_review?: EvaluationReview;
  reviews: EvaluationReview[];
  average_score: number;
  knowledge_preview?: KnowledgePromotionPreview;
};

export type RootCauseFamilyCatalog = {
  families: string[];
};

export type EvaluationReviewInput = Omit<EvaluationReview, 'review_id' | 'run_id' | 'reviewer' | 'created_at' | 'updated_at'>;

export type AnalysisProgressEntry = {
  seq?: number;
  phase?: string;
  message?: string;
  timestamp?: string;
  collector?: string;
  status?: string;
  summary?: string;
  selected_hypothesis?: string;
  hypothesis_ledger?: unknown;
  [key: string]: unknown;
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
  metadata?: Record<string, unknown> & {
    progress_log?: AnalysisProgressEntry[];
    pinned?: boolean;
    operator_correction?: {
      base_run_id?: string;
    };
  };
  first_completed_at?: string;
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
  user_approved_at?: string | null;
  archived_at?: string | null;
  deleted_at?: string | null;
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
  similar_incidents: SimilarIncident[];
  feedback: FeedbackSummary;
  is_analyzing: boolean;
};

export type IncidentDetail = Incident & {
  analysis_run_id?: string;
  active_analysis_run_id?: string;
  analysis_hash?: string;
  analysis_summary: string;
  analysis_detail: string;
  analysis_quality: string;
  root_cause_family?: string;
  capabilities: Record<string, string>;
  missing_data: string[];
  warnings: string[];
  artifacts: Artifact[];
  similar_incidents: SimilarIncident[];
  similar_recent_count: number;
  token_usage?: Record<string, unknown>;
  harness?: Record<string, unknown>;
  confidence_diagnostics?: Record<string, unknown>;
  ontology_reasoning?: Record<string, unknown>;
  feedback: FeedbackSummary;
  alerts: AlertRecord[];
};

export type RecurrenceDay = {
  date: string;
  total: number;
  recurred: number;
  rate: number;
};

export type RecurrenceStats = {
  days: number;
  rate: number;
  total: number;
  recurred: number;
  daily: RecurrenceDay[];
};

export type LLMSpendBucket = {
  calls: number;
  calls_without_usage: number;
  failed_calls: number;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  cost_usd: number;
};

export type LLMSpendDay = LLMSpendBucket & {
  date: string;
};

export type LLMSpendStats = LLMSpendBucket & {
  days: number;
  by_model: Record<string, LLMSpendBucket>;
  daily: LLMSpendDay[];
};

export type KPIBucket = {
  count: number;
  avg_minutes: number;
  p50_minutes: number;
  p90_minutes: number;
};

export type KPIDay = {
  date: string;
  time_to_rca: KPIBucket;
  time_to_resolve: KPIBucket;
};

export type KPIStats = {
  days: number;
  time_to_rca: KPIBucket;
  time_to_resolve: KPIBucket;
  daily: KPIDay[];
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

// Learned knowledge is derived from completed incident analysis. These records
// are intentionally review-only: the dashboard may decide their lifecycle but
// never constructs or mutates their evidence payloads.
export type KnowledgeEvidenceSummary = {
  evidence_id: string;
  entity?: string;
  source?: string;
  source_group?: string;
  predicate?: string;
  polarity?: string;
  coverage?: string;
  quality?: string;
};

export type KnowledgeCandidate = {
  candidate_id: string;
  status: string;
  title?: string;
  summary?: string;
  root_cause_family?: string;
  kind?: string;
  confidence?: number;
  validation_error?: string;
  incident_id?: string;
  supporting_case_count?: number;
  analysis_run_id?: string;
  analysis_hash?: string;
  evidence_summaries?: KnowledgeEvidenceSummary[];
  probe_template_ids?: string[];
  provenance?: Record<string, unknown>;
  created_at?: string;
  decided_at?: string;
  decided_by?: string;
};

export type KnowledgePackage = {
  package_id: string;
  status: string;
  title?: string;
  summary?: string;
  root_cause_family?: string;
  candidate_id?: string;
  confidence?: number;
  provenance?: Record<string, unknown>;
  evidence_summaries?: KnowledgeEvidenceSummary[];
  probe_template_ids?: string[];
  analysis_run_id?: string;
  analysis_hash?: string;
  published_at?: string;
  retired_at?: string;
  mirror_status?: string;
  runtime_status?: string;
  mirror_last_error?: string;
  mirror_updated_at?: string;
};

export type ProbeMetric = {
  template_id: string;
  case_count: number;
  executions: number;
  supports: number;
  refutes: number;
  inconclusive: number;
  linked_evidence_count: number;
  linked_hypothesis_count: number;
  final_diagnosis_tests: number;
  final_diagnosis_supported: number;
};

export type ProbeMetricsSnapshot = {
  case_count: number;
  metrics: ProbeMetric[];
};

export type KnowledgeRuntimeSnapshot = {
  revision: string;
  packages: KnowledgePackage[];
};
