package server

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// CaseSnapshot is the immutable, approval-bound projection of one completed
// analysis. Its payload is never updated after creation; only the approval
// lifecycle can transition between active and revoked.
type CaseSnapshot struct {
	CaseID               string         `json:"case_id"`
	IncidentID           string         `json:"incident_id"`
	AlertID              string         `json:"alert_id,omitempty"`
	RunID                string         `json:"run_id"`
	AnalysisHash         string         `json:"analysis_hash"`
	ApprovalState        string         `json:"approval_state"`
	RootCauseFamily      string         `json:"root_cause_family,omitempty"`
	Mechanism            string         `json:"mechanism,omitempty"`
	MechanismFingerprint string         `json:"mechanism_fingerprint,omitempty"`
	Snapshot             map[string]any `json:"snapshot"`
	ApprovedAt           time.Time      `json:"approved_at"`
	RevokedAt            *time.Time     `json:"revoked_at,omitempty"`
}

func cloneCaseSnapshot(in *CaseSnapshot) CaseSnapshot {
	if in == nil {
		return CaseSnapshot{}
	}
	out := *in
	out.Snapshot = cloneCaseSnapshotPayload(in.Snapshot)
	return out
}

// ApprovedCaseSnapshot returns the current active snapshot for an incident.
// It intentionally does not fall back to the latest run: a run becomes a
// historical prior only after an operator approved this exact analysis hash.
func (s *Store) ApprovedCaseSnapshot(incidentID string) (CaseSnapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	caseID := s.activeCaseByIncident[incidentID]
	snapshot := s.caseSnapshots[caseID]
	if snapshot == nil || snapshot.ApprovalState != "active" {
		return CaseSnapshot{}, false
	}
	return cloneCaseSnapshot(snapshot), true
}

// approveCaseSnapshotLocked materializes the latest completed RCA as an
// immutable snapshot. Approval without a completed/hash-bound RCA remains
// valid for backwards compatibility, but deliberately creates no CaseCard.
func (s *Store) approveCaseSnapshotLocked(incident *Incident, approvedAt time.Time) bool {
	if incident == nil {
		return false
	}
	run := s.latestAnalysisRunForIncidentLocked(incident.IncidentID)
	if run == nil || run.Status != "complete" {
		return true
	}
	hash := strings.TrimSpace(currentAnalysisHash(run))
	if hash == "" {
		return true
	}
	caseID := run.RunID + ":" + hash
	if existing := s.caseSnapshots[caseID]; existing != nil {
		existing.ApprovalState = "active"
		existing.RevokedAt = nil
		if !s.persistCaseSnapshotLifecycleLocked(existing) {
			return false
		}
		s.activeCaseByIncident[incident.IncidentID] = caseID
		return true
	}

	mechanism, fingerprint := caseMechanismFromMetadata(run.Metadata)
	payload := map[string]any{
		"schema_version":       2,
		"analysis_summary":     run.AnalysisSummary,
		"analysis_detail":      run.AnalysisDetail,
		"analysis_quality":     run.AnalysisQuality,
		"root_cause_family":    run.RootCauseFamily,
		"artifacts":            cloneArtifacts(run.Artifacts),
		"metadata":             cloneAnyMap(run.Metadata),
		"incident_status":      incident.Status,
		"incident_fired_at":    incident.FiredAt.UTC().Format(time.RFC3339Nano),
		"incident_resolved_at": formatOptionalTime(incident.ResolvedAt),
	}
	// CaseCard is deliberately a compact, immutable projection.  It carries
	// only already-recorded RCA fields (linked evidence, allow-listed alert
	// context, and operator review outcomes), never a new LLM interpretation.
	payload["case_card"] = s.caseCardSnapshotLocked(incident, run, hash, mechanism, fingerprint)
	snapshot := &CaseSnapshot{
		CaseID:               caseID,
		IncidentID:           incident.IncidentID,
		AlertID:              run.AlertID,
		RunID:                run.RunID,
		AnalysisHash:         hash,
		ApprovalState:        "active",
		RootCauseFamily:      run.RootCauseFamily,
		Mechanism:            mechanism,
		MechanismFingerprint: fingerprint,
		ApprovedAt:           approvedAt,
		Snapshot:             cloneCaseSnapshotPayload(payload),
	}
	if strings.HasPrefix(snapshot.RootCauseFamily, "novel_") &&
		!s.persistNovelCauseRegistryLocked(snapshot) {
		return false
	}
	if !s.persistNewCaseSnapshotLocked(snapshot) {
		return false
	}
	s.caseSnapshots[caseID] = snapshot
	s.activeCaseByIncident[incident.IncidentID] = caseID
	return true
}

func (s *Store) caseCardSnapshotLocked(
	incident *Incident,
	run *AnalysisRun,
	analysisHash, mechanism, fingerprint string,
) map[string]any {
	card := map[string]any{
		"schema_version":         1,
		"historical_prior":       true,
		"approval_analysis_hash": analysisHash,
		"family":                 run.RootCauseFamily,
	}
	if mechanism != "" {
		card["mechanism"] = mechanism
	}
	if fingerprint != "" {
		card["mechanism_fingerprint"] = fingerprint
	}
	if context := s.caseCardContextLocked(incident, run); len(context) > 0 {
		card["context"] = context
	}

	support, contradict := evidenceLinksFromHarness(run)
	if bySource := evidenceBySource(run.Artifacts, support); len(bySource) > 0 {
		card["supporting_evidence_by_source"] = bySource
	}
	if bySource := evidenceBySource(run.Artifacts, contradict); len(bySource) > 0 {
		card["contradicting_evidence_by_source"] = bySource
	}

	if quality, source, success, failed := s.caseReviewProjectionLocked(run.RunID, analysisHash, run.Metadata); quality >= 0 {
		card["quality_score"] = quality
		card["quality_source"] = source
		if len(success) > 0 {
			card["successful_actions"] = success
		}
		if len(failed) > 0 {
			card["failed_actions"] = failed
		}
	}
	return card
}

func (s *Store) caseCardContextLocked(incident *Incident, run *AnalysisRun) map[string]string {
	alert := s.alerts[run.AlertID]
	if alert == nil {
		return nil
	}
	labels := alert.Labels
	annotations := alert.Annotations
	context := map[string]string{}
	for field, keys := range map[string][]string{
		"alert_name":     {"alertname"},
		"cluster":        {"cluster", "cluster_name"},
		"node":           {"node", "node_name", "kubernetes.io/hostname", "kubernetes_io_hostname"},
		"namespace":      {"namespace", "kubernetes_namespace"},
		"project":        {"project", "runai_project", "run.ai/project"},
		"queue":          {"queue", "runai_queue", "run.ai/queue"},
		"workload":       {"workload", "workload_name", "runai_workload", "run.ai/workload"},
		"workload_type":  {"workload_type", "runai_workload_type", "run.ai/workload-type"},
		"component":      {"component", "kubernetes_component", "app.kubernetes.io/component", "app_kubernetes_io_component"},
		"version":        {"version", "runai_version", "app.kubernetes.io/version", "app_kubernetes_io_version"},
		"gpu_model":      {"gpu_model", "nvidia.com/gpu.product", "nvidia_com_gpu_product"},
		"incident_phase": {"incident_phase", "phase"},
	} {
		for _, key := range keys {
			if value := strings.TrimSpace(labels[key]); value != "" {
				context[field] = value
				break
			}
			if value := strings.TrimSpace(annotations[key]); value != "" {
				context[field] = value
				break
			}
		}
	}
	if incident != nil && strings.TrimSpace(incident.Status) != "" {
		context["incident_status_at_approval"] = incident.Status
	}
	return context
}

func evidenceLinksFromHarness(run *AnalysisRun) (map[string]bool, map[string]bool) {
	support, contradict := map[string]bool{}, map[string]bool{}
	if run == nil || run.Metadata == nil {
		return support, contradict
	}
	harness, ok := run.Metadata["harness"].(map[string]any)
	if !ok {
		return support, contradict
	}
	claims, _ := harness["claims"].([]any)
	for _, raw := range claims {
		claim, ok := raw.(map[string]any)
		if !ok || claim["kind"] != "root_cause" {
			continue
		}
		for _, item := range stringSlice(claim["supporting_evidence"]) {
			support[item] = true
		}
		for _, item := range stringSlice(claim["contradicting_evidence"]) {
			contradict[item] = true
		}
		for _, item := range stringSlice(claim["contradiction_evidence_ids"]) {
			contradict[item] = true
		}
		break
	}
	return support, contradict
}

func stringSlice(raw any) []string {
	values, ok := raw.([]any)
	if !ok {
		if strings, ok := raw.([]string); ok {
			return strings
		}
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
			out = append(out, strings.TrimSpace(text))
		}
	}
	return out
}

func evidenceBySource(artifacts []Artifact, selected map[string]bool) map[string][]map[string]string {
	if len(selected) == 0 {
		return nil
	}
	bySource := map[string][]map[string]string{}
	for _, artifact := range artifacts {
		if !selected[artifact.EvidenceID] {
			continue
		}
		source := strings.TrimSpace(artifact.Source)
		if source == "" {
			source = strings.TrimSpace(artifact.Agent)
		}
		if source == "" {
			source = "unknown"
		}
		bySource[source] = append(bySource[source], map[string]string{
			"evidence_id": artifact.EvidenceID,
			"summary":     strings.TrimSpace(artifact.Summary),
		})
	}
	return bySource
}

func (s *Store) caseReviewProjectionLocked(runID, analysisHash string, metadata map[string]any) (int, string, []string, []string) {
	quality, source := harnessQualityScore(metadata)
	successSet, failedSet := map[string]bool{}, map[string]bool{}
	reviewTotal, reviewCount := 0.0, 0
	for _, review := range s.evaluationReviews {
		if review.RunID != runID || review.AnalysisHash != analysisHash {
			continue
		}
		reviewTotal += reviewScore(review.Scores) * 20
		reviewCount++
		action := strings.TrimSpace(review.EffectiveAction)
		if action == "" {
			continue
		}
		switch review.ResolutionOutcome {
		case "resolved", "mitigated":
			successSet[action] = true
		case "ineffective":
			failedSet[action] = true
		}
	}
	if reviewCount > 0 {
		quality = int(reviewTotal/float64(reviewCount) + 0.5)
		source = "operator_review"
	}
	return quality, source, sortedSet(successSet), sortedSet(failedSet)
}

func harnessQualityScore(metadata map[string]any) (int, string) {
	harness, ok := metadata["harness"].(map[string]any)
	if !ok {
		return -1, ""
	}
	score, ok := numberToInt(harness["overall_score"])
	if !ok || score < 0 || score > 100 {
		return -1, ""
	}
	return score, "harness"
}

func numberToInt(raw any) (int, bool) {
	switch value := raw.(type) {
	case int:
		return value, true
	case int64:
		return int(value), true
	case float64:
		return int(value + 0.5), true
	case json.Number:
		parsed, err := value.Int64()
		return int(parsed), err == nil
	default:
		return 0, false
	}
}

func sortedSet(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func (s *Store) revokeCaseSnapshotsLocked(incidentID string, revokedAt time.Time) bool {
	caseID := s.activeCaseByIncident[incidentID]
	if caseID == "" {
		return true
	}
	snapshot := s.caseSnapshots[caseID]
	if snapshot == nil {
		delete(s.activeCaseByIncident, incidentID)
		return true
	}
	snapshot.ApprovalState = "revoked"
	snapshot.RevokedAt = &revokedAt
	if !s.persistCaseSnapshotLifecycleLocked(snapshot) {
		snapshot.ApprovalState = "active"
		snapshot.RevokedAt = nil
		return false
	}
	delete(s.activeCaseByIncident, incidentID)
	return true
}

func caseMechanismFromMetadata(metadata map[string]any) (string, string) {
	if metadata == nil {
		return "", ""
	}
	for _, key := range []string{"reasoning_trace_v2", "ontology_reasoning"} {
		trace, ok := metadata[key].(map[string]any)
		if !ok {
			continue
		}
		mechanism, _ := trace["mechanism"].(string)
		fingerprint, _ := trace["mechanism_fingerprint"].(string)
		if mechanism != "" || fingerprint != "" {
			return strings.TrimSpace(mechanism), strings.TrimSpace(fingerprint)
		}
		if selected, ok := trace["selected_hypothesis"].(map[string]any); ok {
			mechanism, _ = selected["mechanism"].(string)
			fingerprint, _ = selected["mechanism_fingerprint"].(string)
			if mechanism != "" || fingerprint != "" {
				return strings.TrimSpace(mechanism), strings.TrimSpace(fingerprint)
			}
		}
	}
	return "", ""
}

func formatOptionalTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func cloneCaseSnapshotPayload(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	// Do not round-trip through JSON here: json.Unmarshal turns every integral
	// quality score into float64. A CaseCard is an immutable in-memory snapshot
	// as well as a JSON payload, so preserve the original scalar types.
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = cloneCaseSnapshotValue(value)
	}
	return out
}

func cloneCaseSnapshotValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneCaseSnapshotPayload(typed)
	case map[string]string:
		return cloneMap(typed)
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = cloneCaseSnapshotValue(item)
		}
		return out
	case []string:
		return append([]string(nil), typed...)
	case []Artifact:
		return cloneArtifacts(typed)
	case map[string][]map[string]string:
		// Keep the CaseCard projection JSON-shaped for its TypeDB consumer while
		// still preserving scalar types such as the integer quality score.
		out := make(map[string]any, len(typed))
		for source, evidence := range typed {
			copied := make([]any, len(evidence))
			for i, item := range evidence {
				entry := make(map[string]any, len(item))
				for key, text := range item {
					entry[key] = text
				}
				copied[i] = entry
			}
			out[source] = copied
		}
		return out
	default:
		return value
	}
}
