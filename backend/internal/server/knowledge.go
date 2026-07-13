package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	knowledgeCandidateGenerated        = "generated"
	knowledgeCandidateValidationFailed = "validation_failed"
	knowledgeCandidateReady            = "ready_for_review"
	knowledgeCandidateShadow           = "shadow"
	knowledgeCandidateActive           = "active"
	knowledgeCandidateRejected         = "rejected"
	knowledgeCandidateSuperseded       = "superseded"
	knowledgePackageActive             = "active"
	knowledgePackageShadow             = "shadow"
	knowledgePackageRetired            = "retired"
)

// KnowledgeCandidate is a reviewable, incident-derived proposal. It can only
// originate from an approved immutable CaseSnapshot; clients cannot author its
// payload or create packages directly.
type KnowledgeCandidate struct {
	CandidateID          string                     `json:"candidate_id"`
	KnowledgeFingerprint string                     `json:"knowledge_fingerprint"`
	CaseID               string                     `json:"case_id"`
	SupportingCaseIDs    []string                   `json:"supporting_case_ids"`
	SupportingCaseCount  int                        `json:"supporting_case_count"`
	IncidentID           string                     `json:"incident_id"`
	RunID                string                     `json:"run_id"`
	Status               string                     `json:"status"`
	PackageID            string                     `json:"package_id,omitempty"`
	ContentHash          string                     `json:"content_hash"`
	ValidationError      string                     `json:"validation_error,omitempty"`
	Trace                map[string]any             `json:"trace,omitempty"`
	Payload              map[string]any             `json:"payload"`
	CreatedAt            time.Time                  `json:"created_at"`
	UpdatedAt            time.Time                  `json:"updated_at"`
	DecidedAt            *time.Time                 `json:"decided_at,omitempty"`
	DecidedBy            string                     `json:"decided_by,omitempty"`
	DecisionNote         string                     `json:"decision_note,omitempty"`
	Title                string                     `json:"title"`
	Summary              string                     `json:"summary"`
	RootCauseFamily      string                     `json:"root_cause_family"`
	Family               string                     `json:"family"`
	Kind                 string                     `json:"kind"`
	Confidence           float64                    `json:"confidence"`
	Provenance           map[string]any             `json:"provenance"`
	EvidenceSummaries    []KnowledgeEvidenceSummary `json:"evidence_summaries"`
	AnalysisRunID        string                     `json:"analysis_run_id"`
	AnalysisHash         string                     `json:"analysis_hash"`
	RuntimeStatus        string                     `json:"runtime_status"`
	MirrorStatus         string                     `json:"mirror_status"`
	ProbeTemplateIDs     []string                   `json:"probe_template_ids"`
	ProbeBindings        []KnowledgeProbeBinding    `json:"probe_bindings"`
}

type KnowledgeEvidenceSummary struct {
	EvidenceID  string `json:"evidence_id"`
	Source      string `json:"source,omitempty"`
	SourceGroup string `json:"source_group,omitempty"`
	Entity      string `json:"entity,omitempty"`
	Predicate   string `json:"predicate,omitempty"`
	Polarity    string `json:"polarity,omitempty"`
	Coverage    string `json:"coverage,omitempty"`
	Quality     string `json:"quality,omitempty"`
}

// KnowledgeProbeBinding contains stable identifier-only metadata. It never
// includes executable probe arguments, queries, logs, or CaseSnapshot data.
type KnowledgeProbeBinding struct {
	TemplateID       string `json:"template_id"`
	ProbeLocalID     string `json:"probe_local_id"`
	CandidateProbeID string `json:"candidate_probe_id,omitempty"`
	ActiveProbeID    string `json:"active_probe_id,omitempty"`
}

// KnowledgePackage is the immutable public runtime unit produced by approving
// a candidate. Its lifecycle is active -> retired; there is deliberately no
// create or update operation outside candidate approval.
type KnowledgePackage struct {
	PackageID         string                     `json:"package_id"`
	CandidateID       string                     `json:"candidate_id"`
	CaseID            string                     `json:"case_id"`
	Status            string                     `json:"status"`
	Payload           map[string]any             `json:"payload"`
	PublishedAt       time.Time                  `json:"published_at"`
	RetiredAt         *time.Time                 `json:"retired_at,omitempty"`
	RetiredBy         string                     `json:"retired_by,omitempty"`
	RetirementNote    string                     `json:"retirement_note,omitempty"`
	Title             string                     `json:"title"`
	Summary           string                     `json:"summary"`
	RootCauseFamily   string                     `json:"root_cause_family"`
	Family            string                     `json:"family"`
	Kind              string                     `json:"kind"`
	Confidence        float64                    `json:"confidence"`
	Provenance        map[string]any             `json:"provenance"`
	EvidenceSummaries []KnowledgeEvidenceSummary `json:"evidence_summaries"`
	AnalysisRunID     string                     `json:"analysis_run_id"`
	AnalysisHash      string                     `json:"analysis_hash"`
	RuntimeStatus     string                     `json:"runtime_status"`
	MirrorStatus      string                     `json:"mirror_status"`
	ProbeTemplateIDs  []string                   `json:"probe_template_ids"`
	ProbeBindings     []KnowledgeProbeBinding    `json:"probe_bindings"`
	MirrorLastError   string                     `json:"mirror_last_error,omitempty"`
	MirrorUpdatedAt   *time.Time                 `json:"mirror_updated_at,omitempty"`
	Compiled          map[string]any             `json:"compiled"`
}

// KnowledgeEvent is an append-only audit record for candidate/package state.
type KnowledgeEvent struct {
	EventID     string    `json:"event_id"`
	CandidateID string    `json:"candidate_id,omitempty"`
	PackageID   string    `json:"package_id,omitempty"`
	Type        string    `json:"type"`
	Actor       string    `json:"actor,omitempty"`
	Note        string    `json:"note,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type KnowledgeDecisionRequest struct {
	Actor string `json:"actor,omitempty"`
	Note  string `json:"note,omitempty"`
}

type KnowledgeRuntimeSnapshot struct {
	Revision string             `json:"revision"`
	Packages []KnowledgePackage `json:"packages"`
}

// ProbeMetric is derived on demand from active, immutable trace-v3 case
// snapshots. It deliberately keeps no tool input or evidence content.
type ProbeMetric struct {
	TemplateID              string `json:"template_id"`
	CaseCount               int    `json:"case_count"`
	Executions              int    `json:"executions"`
	Supports                int    `json:"supports"`
	Refutes                 int    `json:"refutes"`
	Inconclusive            int    `json:"inconclusive"`
	LinkedEvidenceCount     int    `json:"linked_evidence_count"`
	LinkedHypothesisCount   int    `json:"linked_hypothesis_count"`
	FinalDiagnosisTests     int    `json:"final_diagnosis_tests"`
	FinalDiagnosisSupported int    `json:"final_diagnosis_supported"`
}

type ProbeMetricsSnapshot struct {
	CaseCount int           `json:"case_count"`
	Metrics   []ProbeMetric `json:"metrics"`
}

func cloneKnowledgeCandidate(in *KnowledgeCandidate) KnowledgeCandidate {
	if in == nil {
		return KnowledgeCandidate{}
	}
	out := *in
	out.Trace = cloneCaseSnapshotPayload(in.Trace)
	out.Payload = cloneCaseSnapshotPayload(in.Payload)
	out.SupportingCaseIDs = append([]string(nil), in.SupportingCaseIDs...)
	out.Provenance = cloneCaseSnapshotPayload(in.Provenance)
	out.EvidenceSummaries = append([]KnowledgeEvidenceSummary(nil), in.EvidenceSummaries...)
	out.ProbeTemplateIDs = append([]string(nil), in.ProbeTemplateIDs...)
	out.ProbeBindings = append([]KnowledgeProbeBinding(nil), in.ProbeBindings...)
	return out
}

func cloneKnowledgePackage(in *KnowledgePackage) KnowledgePackage {
	if in == nil {
		return KnowledgePackage{}
	}
	out := *in
	out.Payload = cloneCaseSnapshotPayload(in.Payload)
	out.Provenance = cloneCaseSnapshotPayload(in.Provenance)
	out.Compiled = cloneCaseSnapshotPayload(in.Compiled)
	out.EvidenceSummaries = append([]KnowledgeEvidenceSummary(nil), in.EvidenceSummaries...)
	out.ProbeTemplateIDs = append([]string(nil), in.ProbeTemplateIDs...)
	out.ProbeBindings = append([]KnowledgeProbeBinding(nil), in.ProbeBindings...)
	return out
}

func knowledgeCandidateForSnapshot(snapshot *CaseSnapshot) *KnowledgeCandidate {
	return knowledgeCandidateForSnapshotWithOutcome(snapshot, false)
}

func knowledgeCandidateForSnapshotWithOutcome(snapshot *CaseSnapshot, operatorOutcome bool) *KnowledgeCandidate {
	if snapshot == nil {
		return nil
	}
	trace := knowledgeTraceV3(snapshot.Snapshot)
	// Legacy traces are intentionally skipped. There is no safe way to infer
	// v3 graph relationships from v2 or trace-less history.
	if trace == nil {
		return nil
	}
	if !operatorOutcome && !caseSnapshotHasOperatorOutcome(snapshot) {
		return nil
	}
	payload, validationError := compiledKnowledgePayload(snapshot, trace)
	fingerprint := knowledgeFingerprint(payload)
	contentHash := knowledgeContentHash(trace, payload)
	candidate := &KnowledgeCandidate{
		CandidateID: "KNC-" + fingerprint[:16] + "-" + contentHash[:16], KnowledgeFingerprint: fingerprint,
		CaseID: snapshot.CaseID, SupportingCaseIDs: []string{snapshot.CaseID}, SupportingCaseCount: 1, IncidentID: snapshot.IncidentID, RunID: snapshot.RunID,
		Status: knowledgeCandidateGenerated, Trace: trace, Payload: payload, CreatedAt: snapshot.ApprovedAt, UpdatedAt: snapshot.ApprovedAt,
		ContentHash: contentHash,
	}
	if validationError != "" {
		candidate.Status, candidate.ValidationError = knowledgeCandidateValidationFailed, validationError
	} else {
		candidate.Status = knowledgeCandidateReady
	}
	hydrateKnowledgeCandidate(candidate)
	return candidate
}

func caseSnapshotHasOperatorOutcome(snapshot *CaseSnapshot) bool {
	if snapshot == nil {
		return false
	}
	card, _ := snapshot.Snapshot["case_card"].(map[string]any)
	if card == nil {
		return false
	}
	for _, outcome := range sanitizeStringSlice(card["operator_resolution_outcomes"]) {
		if outcome == "resolved" || outcome == "mitigated" {
			return true
		}
	}
	return false
}

// knowledgeTraceV3 intentionally reads only the version-three trace when it
// is present. Older trace formats remain in the immutable payload, but cannot
// silently be represented as a v3 knowledge assertion.
func knowledgeTraceV3(payload map[string]any) map[string]any {
	metadata, _ := payload["metadata"].(map[string]any)
	if metadata == nil {
		return nil
	}
	for _, key := range []string{"reasoning_trace_v3", "trace_v3"} {
		if trace, ok := metadata[key].(map[string]any); ok {
			if version, ok := numberToInt(trace["schema_version"]); !ok || version != 3 {
				return nil
			}
			return sanitizeTraceV3(trace)
		}
	}
	return nil
}

// sanitizeTraceV3 preserves the interoperable graph contract and its exact IDs
// while intentionally dropping any unrecognized fields (queries, arguments,
// raw tool output, and log excerpts are never knowledge-package data).
func sanitizeTraceV3(trace map[string]any) map[string]any {
	out := map[string]any{"schema_version": 3}
	if hypotheses := sanitizeTraceObjects(trace["hypotheses"], []string{"hypothesis_id", "family", "mechanism", "status", "confidence"}, map[string][]string{"evidence_for": nil, "evidence_against": nil}); len(hypotheses) > 0 {
		out["hypotheses"] = hypotheses
	}
	if evidence := sanitizeTraceObjects(trace["evidence"], []string{"evidence_id", "entity", "source", "source_group", "predicate", "polarity", "coverage", "quality"}, nil); len(evidence) > 0 {
		for _, item := range evidence {
			if raw, ok := item.(map[string]any); ok {
				if original, ok := traceEvidenceByID(trace, stringValue(raw["evidence_id"])); ok {
					if window, ok := original["observation_window"].(map[string]any); ok {
						raw["observation_window"] = sanitizeObservationWindow(window)
					}
				}
			}
		}
		out["evidence"] = evidence
	}
	if probes := sanitizeTraceObjects(trace["probe_executions"], []string{"execution_id", "template_id", "tool", "verdict", "executed_at"}, map[string][]string{"hypothesis_ids": nil, "evidence_ids": nil}); len(probes) > 0 {
		out["probe_executions"] = probes
	}
	if links := sanitizeStringSlice(trace["rejected_evidence_links"]); len(links) > 0 {
		out["rejected_evidence_links"] = links
	}
	if stop := strings.TrimSpace(stringValue(trace["stop_reason"])); stop != "" {
		out["stop_reason"] = stop
	}
	return out
}

func sanitizeTraceObjects(raw any, fields []string, listFields map[string][]string) []any {
	items, _ := raw.([]any)
	if items == nil {
		if typed, ok := raw.([]map[string]any); ok {
			items = make([]any, len(typed))
			for i := range typed {
				items[i] = typed[i]
			}
		}
	}
	out := make([]any, 0, len(items))
	for _, item := range items {
		source, ok := item.(map[string]any)
		if !ok {
			continue
		}
		clean := map[string]any{}
		for _, field := range fields {
			if value, ok := source[field]; ok {
				clean[field] = value
			}
		}
		for field := range listFields {
			if values := sanitizeStringSlice(source[field]); len(values) > 0 {
				clean[field] = values
			}
		}
		out = append(out, clean)
	}
	return out
}

func sanitizeStringSlice(raw any) []string { values := stringSlice(raw); return values }
func traceEvidenceByID(trace map[string]any, id string) (map[string]any, bool) {
	items, _ := trace["evidence"].([]any)
	for _, item := range items {
		value, ok := item.(map[string]any)
		if ok && stringValue(value["evidence_id"]) == id {
			return value, true
		}
	}
	return nil, false
}
func sanitizeObservationWindow(window map[string]any) map[string]any {
	out := map[string]any{}
	for _, field := range []string{"start", "end"} {
		if value := strings.TrimSpace(stringValue(window[field])); value != "" {
			out[field] = value
		}
	}
	return out
}

// compiledKnowledgePayload is intentionally a narrow public representation.
// It excludes analysis prose, artifacts, raw evidence, tool queries, and logs.
func compiledKnowledgePayload(snapshot *CaseSnapshot, trace map[string]any) (map[string]any, string) {
	if snapshot == nil {
		return nil, "missing source case snapshot"
	}
	card, _ := snapshot.Snapshot["case_card"].(map[string]any)
	metadata, _ := snapshot.Snapshot["metadata"].(map[string]any)
	harness, _ := metadata["harness"].(map[string]any)
	if harness == nil {
		return nil, "missing validation harness"
	}
	quality, source := harnessQualityScore(metadata)
	if quality < 80 {
		return nil, "quality score must be at least 80"
	}
	if !harnessHardGatesPassed(harness) {
		return nil, "all non-empty harness hard gates must pass"
	}
	hypothesis, support, contradiction, err := readyTraceV3Hypothesis(trace, snapshot.RootCauseFamily, snapshot.Mechanism)
	if err != "" {
		return nil, err
	}
	if len(support) == 0 {
		return nil, "missing supporting evidence"
	}
	if len(contradiction) > 0 {
		return nil, "unresolved contradicting evidence"
	}
	if errorText := canonicalSupportingEvidenceError(trace, support); errorText != "" {
		return nil, errorText
	}
	hypothesisID := stringValue(hypothesis["hypothesis_id"])
	probeTemplateIDs := traceV3LinkedProbeTemplateIDs(trace, hypothesisID, support)
	if len(probeTemplateIDs) == 0 {
		return nil, "missing probe execution linked to hypothesis evidence"
	}
	if strings.TrimSpace(stringValue(snapshot.Snapshot["analysis_summary"])) == "" || strings.TrimSpace(stringValue(snapshot.Snapshot["analysis_detail"])) == "" {
		return nil, "missing analysis result"
	}
	family, mechanism := stringValue(hypothesis["family"]), stringValue(hypothesis["mechanism"])
	confidence, _ := numberToFloat(hypothesis["confidence"])
	evidenceSummaries, predicates := traceEvidenceSummaries(trace, support)
	payload := map[string]any{
		"schema_version": 1, "source_case_id": snapshot.CaseID, "root_cause_family": snapshot.RootCauseFamily,
		"quality_score": quality, "quality_source": source, "hypothesis_id": hypothesis["hypothesis_id"],
		"family": family, "mechanism": mechanism, "confidence": confidence, "supporting_evidence_ids": sortedStringSet(support),
		"title": family, "summary": "Evidence-backed " + family + " — " + mechanism,
		"provenance":         map[string]any{"source": "approved_case_snapshot", "case_id": snapshot.CaseID, "incident_id": snapshot.IncidentID},
		"evidence_summaries": evidenceSummaries, "analysis_run_id": snapshot.RunID, "analysis_hash": snapshot.AnalysisHash,
		"runtime_status": "not_published", "mirror_status": "current",
		"compiled": map[string]any{
			"failure_modes": []any{map[string]any{
				"family": family,
				"symptoms": []any{map[string]any{
					"name": mechanism, "keywords": safeKnowledgeKeywords(append([]string{mechanism}, predicates...)), "actions": []any{},
				}},
			}},
			"probe_template_ids": map[string]any{family: probeTemplateIDs},
		},
	}
	if context, ok := card["context"].(map[string]string); ok && len(context) > 0 {
		payload["context"] = cloneMap(context)
	}
	if context, ok := card["context"].(map[string]any); ok && len(context) > 0 {
		payload["context"] = cloneCaseSnapshotPayload(context)
	}
	return payload, ""
}

func harnessHardGatesPassed(harness map[string]any) bool {
	if harness == nil {
		return false
	}
	raw, ok := harness["hard_gates"]
	if !ok {
		return false
	}
	count := 0
	switch gates := raw.(type) {
	case map[string]bool:
		for _, violation := range gates {
			count++
			if violation {
				return false
			}
		}
	case map[string]any:
		for _, rawViolation := range gates {
			violation, ok := rawViolation.(bool)
			if !ok || violation {
				return false
			}
			count++
		}
	default:
		return false
	}
	return count > 0
}

func canonicalSupportingEvidenceError(trace map[string]any, support map[string]bool) string {
	evidence, _ := trace["evidence"].([]any)
	byID := map[string]map[string]any{}
	for _, raw := range evidence {
		if item, ok := raw.(map[string]any); ok {
			byID[stringValue(item["evidence_id"])] = item
		}
	}
	sourceGroups := map[string]bool{}
	for evidenceID := range support {
		item := byID[evidenceID]
		if item == nil {
			return "trace references unknown supporting evidence"
		}
		coverage := stringValue(item["coverage"])
		if stringValue(item["polarity"]) != "present" || (coverage != "scoped" && coverage != "partial") {
			return "supporting evidence must use canonical present polarity and scoped or partial coverage"
		}
		entity, sourceGroup := strings.TrimSpace(stringValue(item["entity"])), strings.TrimSpace(stringValue(item["source_group"]))
		if entity == "" || sourceGroup == "" {
			return "supporting evidence requires entity and source_group"
		}
		window, _ := item["observation_window"].(map[string]any)
		if window == nil || strings.TrimSpace(stringValue(window["start"])) == "" || strings.TrimSpace(stringValue(window["end"])) == "" {
			return "supporting evidence requires observation window start and end"
		}
		sourceGroups[sourceGroup] = true
	}
	if len(sourceGroups) < 2 {
		return "supporting evidence requires at least two source groups"
	}
	return ""
}

func traceEvidenceSummaries(trace map[string]any, selected map[string]bool) ([]KnowledgeEvidenceSummary, []string) {
	items, _ := trace["evidence"].([]any)
	summaries, predicates := []KnowledgeEvidenceSummary{}, []string{}
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok || !selected[stringValue(item["evidence_id"])] {
			continue
		}
		summary := KnowledgeEvidenceSummary{EvidenceID: stringValue(item["evidence_id"]), Source: stringValue(item["source"]), SourceGroup: stringValue(item["source_group"]), Entity: stringValue(item["entity"]), Predicate: stringValue(item["predicate"]), Polarity: stringValue(item["polarity"]), Coverage: stringValue(item["coverage"]), Quality: stringValue(item["quality"])}
		summaries = append(summaries, summary)
		predicates = append(predicates, summary.Predicate)
	}
	return summaries, predicates
}

var safeKeywordSplit = regexp.MustCompile(`[^a-z0-9]+`)

func safeKnowledgeKeywords(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		for _, token := range safeKeywordSplit.Split(strings.ToLower(value), -1) {
			if len(token) < 2 || seen[token] {
				continue
			}
			seen[token] = true
			out = append(out, token)
		}
	}
	return out
}

func hydrateKnowledgeCandidate(candidate *KnowledgeCandidate) {
	if candidate == nil {
		return
	}
	candidate.Title, candidate.Summary = stringValue(candidate.Payload["title"]), stringValue(candidate.Payload["summary"])
	candidate.RootCauseFamily, candidate.Family = stringValue(candidate.Payload["root_cause_family"]), stringValue(candidate.Payload["family"])
	candidate.Confidence, _ = numberToFloat(candidate.Payload["confidence"])
	candidate.Provenance, _ = candidate.Payload["provenance"].(map[string]any)
	candidate.AnalysisRunID, candidate.AnalysisHash = stringValue(candidate.Payload["analysis_run_id"]), stringValue(candidate.Payload["analysis_hash"])
	candidate.RuntimeStatus, candidate.MirrorStatus = stringValue(candidate.Payload["runtime_status"]), stringValue(candidate.Payload["mirror_status"])
	candidate.EvidenceSummaries = knowledgeEvidenceSummaries(candidate.Payload["evidence_summaries"])
	if compiled, ok := candidate.Payload["compiled"].(map[string]any); ok {
		candidate.ProbeTemplateIDs = compiledProbeTemplateIDs(compiled["probe_template_ids"])
		candidate.Kind = compiledKnowledgeKind(compiled)
	}
	candidate.ProbeBindings = candidateProbeBindings(candidate.CandidateID, candidate.ProbeTemplateIDs)
	if candidate.Provenance == nil {
		candidate.Provenance = map[string]any{}
	}
}

func hydrateKnowledgePackage(pkg *KnowledgePackage) {
	if pkg == nil {
		return
	}
	pkg.Title, pkg.Summary = stringValue(pkg.Payload["title"]), stringValue(pkg.Payload["summary"])
	pkg.RootCauseFamily, pkg.Family = stringValue(pkg.Payload["root_cause_family"]), stringValue(pkg.Payload["family"])
	pkg.Confidence, _ = numberToFloat(pkg.Payload["confidence"])
	pkg.Provenance, _ = pkg.Payload["provenance"].(map[string]any)
	pkg.AnalysisRunID, pkg.AnalysisHash = stringValue(pkg.Payload["analysis_run_id"]), stringValue(pkg.Payload["analysis_hash"])
	pkg.RuntimeStatus = stringValue(pkg.Payload["runtime_status"])
	if pkg.MirrorStatus == "" {
		pkg.MirrorStatus = stringValue(pkg.Payload["mirror_status"])
	}
	pkg.Compiled, _ = pkg.Payload["compiled"].(map[string]any)
	pkg.Kind = compiledKnowledgeKind(pkg.Compiled)
	pkg.EvidenceSummaries = knowledgeEvidenceSummaries(pkg.Payload["evidence_summaries"])
	pkg.ProbeTemplateIDs = compiledProbeTemplateIDs(pkg.Compiled["probe_template_ids"])
	pkg.ProbeBindings = activeProbeBindings(pkg.PackageID, pkg.ProbeTemplateIDs)
	if pkg.Provenance == nil {
		pkg.Provenance = map[string]any{}
	}
	if pkg.Compiled == nil {
		pkg.Compiled = map[string]any{}
	}
}

func compiledKnowledgeKind(compiled map[string]any) string {
	if len(compiledFailureModes(compiled["failure_modes"])) > 0 {
		return "failure_mode"
	}
	if len(compiledFailureModes(compiled["known_issues"])) > 0 {
		return "known_issue"
	}
	return ""
}

func compiledFailureModes(raw any) []any { values, _ := raw.([]any); return values }

func probeLocalID(templateID string) string {
	if _, local, ok := strings.Cut(strings.TrimSpace(templateID), ":"); ok && local != "" {
		return local
	}
	return strings.TrimSpace(templateID)
}

func candidateProbeBindings(candidateID string, templateIDs []string) []KnowledgeProbeBinding {
	bindings := make([]KnowledgeProbeBinding, 0, len(templateIDs))
	for _, templateID := range templateIDs {
		local := probeLocalID(templateID)
		bindings = append(bindings, KnowledgeProbeBinding{TemplateID: templateID, ProbeLocalID: local, CandidateProbeID: candidateID + ":" + local})
	}
	return bindings
}

func activeProbeBindings(packageID string, templateIDs []string) []KnowledgeProbeBinding {
	bindings := make([]KnowledgeProbeBinding, 0, len(templateIDs))
	for _, templateID := range templateIDs {
		local := probeLocalID(templateID)
		bindings = append(bindings, KnowledgeProbeBinding{TemplateID: templateID, ProbeLocalID: local, ActiveProbeID: packageID + ":v1:" + local})
	}
	return bindings
}

// compiledProbeTemplateIDs flattens the Agent runtime contract
// {family: [template_id...]} into a deterministic review DTO list.
func compiledProbeTemplateIDs(raw any) []string {
	if direct := sanitizeStringSlice(raw); len(direct) > 0 {
		return direct
	}
	families, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	keys := make([]string, 0, len(families))
	for family := range families {
		keys = append(keys, family)
	}
	sort.Strings(keys)
	seen, out := map[string]bool{}, []string{}
	for _, family := range keys {
		for _, id := range sanitizeStringSlice(families[family]) {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

func knowledgeEvidenceSummaries(raw any) []KnowledgeEvidenceSummary {
	values, _ := raw.([]any)
	if values == nil {
		if typed, ok := raw.([]KnowledgeEvidenceSummary); ok {
			return append([]KnowledgeEvidenceSummary(nil), typed...)
		}
	}
	out := make([]KnowledgeEvidenceSummary, 0, len(values))
	for _, raw := range values {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, KnowledgeEvidenceSummary{EvidenceID: stringValue(item["evidence_id"]), Source: stringValue(item["source"]), SourceGroup: stringValue(item["source_group"]), Entity: stringValue(item["entity"]), Predicate: stringValue(item["predicate"]), Polarity: stringValue(item["polarity"]), Coverage: stringValue(item["coverage"]), Quality: stringValue(item["quality"])})
	}
	return out
}

func readyTraceV3Hypothesis(trace map[string]any, finalFamily, finalMechanism string) (map[string]any, map[string]bool, map[string]bool, string) {
	hypotheses, _ := trace["hypotheses"].([]any)
	evidence, _ := trace["evidence"].([]any)
	knownEvidence := map[string]bool{}
	for _, raw := range evidence {
		if item, ok := raw.(map[string]any); ok && stringValue(item["evidence_id"]) != "" {
			knownEvidence[stringValue(item["evidence_id"])] = true
		}
	}
	selectMatching := func(status string) []map[string]any {
		matches := []map[string]any{}
		for _, raw := range hypotheses {
			hypothesis, ok := raw.(map[string]any)
			if !ok || strings.ToLower(stringValue(hypothesis["status"])) != status {
				continue
			}
			family, mechanism := strings.TrimSpace(stringValue(hypothesis["family"])), strings.TrimSpace(stringValue(hypothesis["mechanism"]))
			if family != strings.TrimSpace(finalFamily) || (strings.TrimSpace(finalMechanism) != "" && mechanism != strings.TrimSpace(finalMechanism)) {
				continue
			}
			matches = append(matches, hypothesis)
		}
		return matches
	}
	selected := selectMatching("selected")
	if len(selected) > 1 {
		return nil, nil, nil, "multiple selected trace-v3 hypotheses match final root cause"
	}
	if len(selected) == 0 {
		selected = selectMatching("supported")
	}
	if len(selected) != 1 {
		return nil, nil, nil, "expected exactly one supported trace-v3 hypothesis matching final root cause"
	}
	for _, hypothesis := range selected {
		id, family, mechanism := strings.TrimSpace(stringValue(hypothesis["hypothesis_id"])), strings.TrimSpace(stringValue(hypothesis["family"])), strings.TrimSpace(stringValue(hypothesis["mechanism"]))
		if id == "" || family == "" || mechanism == "" {
			return nil, nil, nil, "selected trace hypothesis is incomplete"
		}
		confidence, ok := numberToFloat(hypothesis["confidence"])
		if !ok || confidence < 0.7 {
			return nil, nil, nil, "selected trace hypothesis confidence must be at least 0.7"
		}
		support, against := map[string]bool{}, map[string]bool{}
		for _, value := range sanitizeStringSlice(hypothesis["evidence_for"]) {
			if !knownEvidence[value] {
				return nil, nil, nil, "trace references unknown supporting evidence"
			}
			support[value] = true
		}
		for _, value := range sanitizeStringSlice(hypothesis["evidence_against"]) {
			if !knownEvidence[value] {
				return nil, nil, nil, "trace references unknown contradicting evidence"
			}
			against[value] = true
		}
		return hypothesis, support, against, ""
	}
	return nil, nil, nil, "missing selected trace-v3 hypothesis"
}

func traceV3HasLinkedProbe(trace map[string]any, hypothesisID string, evidence map[string]bool) bool {
	return len(traceV3LinkedProbeTemplateIDs(trace, hypothesisID, evidence)) > 0
}

func traceV3LinkedProbeTemplateIDs(trace map[string]any, hypothesisID string, evidence map[string]bool) []string {
	probes, _ := trace["probe_executions"].([]any)
	seen, ids := map[string]bool{}, []string{}
	for _, raw := range probes {
		probe, ok := raw.(map[string]any)
		if !ok || stringValue(probe["execution_id"]) == "" || stringValue(probe["verdict"]) == "" || stringValue(probe["template_id"]) == "" {
			continue
		}
		hasHypothesis, hasEvidence := false, false
		for _, id := range sanitizeStringSlice(probe["hypothesis_ids"]) {
			hasHypothesis = hasHypothesis || id == hypothesisID
		}
		for _, id := range sanitizeStringSlice(probe["evidence_ids"]) {
			hasEvidence = hasEvidence || evidence[id]
		}
		if hasHypothesis && hasEvidence {
			id := stringValue(probe["template_id"])
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	return ids
}
func numberToFloat(raw any) (float64, bool) {
	switch value := raw.(type) {
	case float64:
		return value, true
	case float32:
		return float64(value), true
	case int:
		return float64(value), true
	case int64:
		return float64(value), true
	case json.Number:
		parsed, err := value.Float64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

func sortedStringSet(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
func stringValue(value any) string { text, _ := value.(string); return text }
func knowledgeContentHash(trace, payload map[string]any) string {
	digest := sha256.Sum256(mustJSON(map[string]any{"trace": trace, "compiled": payload["compiled"], "family": payload["family"], "mechanism": payload["mechanism"]}))
	return hex.EncodeToString(digest[:])
}

func knowledgeFingerprint(payload map[string]any) string {
	digest := sha256.Sum256(mustJSON(map[string]any{"family": payload["family"], "mechanism": payload["mechanism"], "root_cause_family": payload["root_cause_family"]}))
	return hex.EncodeToString(digest[:])
}

func (s *Store) ListKnowledgeCandidates(status string) []KnowledgeCandidate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]KnowledgeCandidate, 0, len(s.knowledgeCandidates))
	for _, candidate := range s.knowledgeCandidates {
		if status == "" || candidate.Status == status {
			items = append(items, cloneKnowledgeCandidate(candidate))
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	return items
}

func (s *Store) KnowledgeCandidate(id string) (KnowledgeCandidate, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	candidate := s.knowledgeCandidates[id]
	if candidate == nil {
		return KnowledgeCandidate{}, false
	}
	return cloneKnowledgeCandidate(candidate), true
}

func (s *Store) ListKnowledgePackages(includeRetired bool) []KnowledgePackage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]KnowledgePackage, 0, len(s.knowledgePackages))
	for _, pkg := range s.knowledgePackages {
		if includeRetired || pkg.Status == knowledgePackageActive {
			items = append(items, cloneKnowledgePackage(pkg))
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].PublishedAt.After(items[j].PublishedAt) })
	return items
}

func (s *Store) KnowledgePackage(id string) (KnowledgePackage, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pkg := s.knowledgePackages[id]
	if pkg == nil {
		return KnowledgePackage{}, false
	}
	return cloneKnowledgePackage(pkg), true
}

func (s *Store) KnowledgeRuntimeSnapshot() KnowledgeRuntimeSnapshot {
	packages := s.ListKnowledgePackages(false)
	// Revision is a stable content hash, suitable for the Agent's ETag cache.
	// It intentionally includes only active package state, not request time.
	payload := mustJSON(packages)
	digest := sha256.Sum256(payload)
	return KnowledgeRuntimeSnapshot{Revision: hex.EncodeToString(digest[:]), Packages: packages}
}

// ProbeMetrics aggregates only active approved snapshots. This keeps the
// metric reproducible from immutable evidence while excluding revoked cases.
func (s *Store) ProbeMetrics() ProbeMetricsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	metrics := map[string]*ProbeMetric{}
	cases := 0
	for _, snapshot := range s.caseSnapshots {
		if snapshot == nil || snapshot.ApprovalState != "active" {
			continue
		}
		trace := knowledgeTraceV3(snapshot.Snapshot)
		if trace == nil {
			continue
		}
		cases++
		selected := selectedTraceHypothesisIDs(trace, snapshot.RootCauseFamily)
		seenTemplates := map[string]bool{}
		probes, _ := trace["probe_executions"].([]any)
		for _, raw := range probes {
			probe, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			templateID := strings.TrimSpace(stringValue(probe["template_id"]))
			if templateID == "" {
				continue
			}
			metric := metrics[templateID]
			if metric == nil {
				metric = &ProbeMetric{TemplateID: templateID}
				metrics[templateID] = metric
			}
			if !seenTemplates[templateID] {
				metric.CaseCount++
				seenTemplates[templateID] = true
			}
			metric.Executions++
			switch strings.ToLower(strings.TrimSpace(stringValue(probe["verdict"]))) {
			case "supports", "confirmed":
				metric.Supports++
			case "refutes", "refuted", "contradicted":
				metric.Refutes++
			default:
				metric.Inconclusive++
			}
			evidenceIDs, hypothesisIDs := sanitizeStringSlice(probe["evidence_ids"]), sanitizeStringSlice(probe["hypothesis_ids"])
			metric.LinkedEvidenceCount += len(evidenceIDs)
			metric.LinkedHypothesisCount += len(hypothesisIDs)
			if intersectsStringSet(hypothesisIDs, selected) {
				metric.FinalDiagnosisTests++
				if verdictSupports(stringValue(probe["verdict"])) {
					metric.FinalDiagnosisSupported++
				}
			}
		}
	}
	items := make([]ProbeMetric, 0, len(metrics))
	for _, metric := range metrics {
		items = append(items, *metric)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].TemplateID < items[j].TemplateID })
	return ProbeMetricsSnapshot{CaseCount: cases, Metrics: items}
}

func selectedTraceHypothesisIDs(trace map[string]any, family string) map[string]bool {
	selected := map[string]bool{}
	hypotheses, _ := trace["hypotheses"].([]any)
	for _, raw := range hypotheses {
		hypothesis, ok := raw.(map[string]any)
		if !ok || stringValue(hypothesis["family"]) != family || stringValue(hypothesis["status"]) != "selected" {
			continue
		}
		if id := strings.TrimSpace(stringValue(hypothesis["hypothesis_id"])); id != "" {
			selected[id] = true
		}
	}
	return selected
}

func intersectsStringSet(values []string, set map[string]bool) bool {
	for _, value := range values {
		if set[value] {
			return true
		}
	}
	return false
}

func verdictSupports(verdict string) bool {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "supports", "confirmed":
		return true
	default:
		return false
	}
}

func (s *Store) ApproveKnowledgeCandidate(id string, request KnowledgeDecisionRequest) (KnowledgeCandidate, KnowledgePackage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := s.knowledgeCandidates[id]
	if candidate == nil {
		return KnowledgeCandidate{}, KnowledgePackage{}, errors.New("knowledge candidate not found")
	}
	if candidate.Status != knowledgeCandidateReady {
		return KnowledgeCandidate{}, KnowledgePackage{}, errors.New("knowledge candidate is not ready for review")
	}
	snapshot := s.caseSnapshots[candidate.CaseID]
	validated := knowledgeCandidateForSnapshot(snapshot)
	if validated == nil || validated.Status != knowledgeCandidateReady || validated.ContentHash != candidate.ContentHash {
		return KnowledgeCandidate{}, KnowledgePackage{}, errors.New("knowledge candidate failed content-hash revalidation")
	}
	now := time.Now().UTC()
	actor, note := knowledgeActor(request.Actor), strings.TrimSpace(request.Note)
	var prior *KnowledgePackage
	for _, pkg := range s.knowledgePackages {
		if pkg == nil || pkg.Status != knowledgePackageActive || pkg.CandidateID == candidate.CandidateID {
			continue
		}
		priorCandidate := s.knowledgeCandidates[pkg.CandidateID]
		if priorCandidate != nil && priorCandidate.KnowledgeFingerprint == candidate.KnowledgeFingerprint {
			prior = pkg
			break
		}
	}
	pkgPayload := cloneCaseSnapshotPayload(candidate.Payload)
	pkgPayload["runtime_status"] = knowledgePackageActive
	pkgPayload["mirror_status"] = "pending"
	pkg := &KnowledgePackage{PackageID: "KPK-" + candidate.CaseID, CandidateID: candidate.CandidateID, CaseID: candidate.CaseID, Status: knowledgePackageActive, Payload: pkgPayload, PublishedAt: now, MirrorStatus: "pending", MirrorUpdatedAt: &now}
	hydrateKnowledgePackage(pkg)
	event := s.newKnowledgeEventLocked(candidate.CandidateID, pkg.PackageID, "candidate_approved", actor, note, now)
	updated := cloneKnowledgeCandidate(candidate)
	updated.Payload["runtime_status"] = knowledgePackageActive
	updated.Status, updated.PackageID, updated.DecidedAt, updated.DecidedBy, updated.DecisionNote, updated.UpdatedAt = knowledgeCandidateActive, pkg.PackageID, &now, actor, note, now
	hydrateKnowledgeCandidate(&updated)
	if !s.persistKnowledgeApprovalLocked(&updated, pkg, prior, event) {
		return KnowledgeCandidate{}, KnowledgePackage{}, errors.New("could not persist knowledge candidate approval")
	}
	*candidate = updated
	if prior != nil {
		prior.Status, prior.RetiredAt, prior.RetiredBy, prior.RetirementNote = knowledgePackageRetired, &now, actor, "superseded by "+candidate.CandidateID
		if priorCandidate := s.knowledgeCandidates[prior.CandidateID]; priorCandidate != nil {
			priorCandidate.Status = knowledgeCandidateSuperseded
			priorCandidate.UpdatedAt = now
		}
	}
	s.knowledgePackages[pkg.PackageID] = pkg
	s.knowledgeEvents[event.EventID] = event
	return cloneKnowledgeCandidate(candidate), cloneKnowledgePackage(pkg), nil
}

// ShadowKnowledgeCandidate publishes a validated package for review without
// exposing it to the active runtime snapshot. A later explicit activation is
// required, so an approved case cannot change RCA ranking by accident.
func (s *Store) ShadowKnowledgeCandidate(id string, request KnowledgeDecisionRequest) (KnowledgeCandidate, KnowledgePackage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := s.knowledgeCandidates[id]
	if candidate == nil {
		return KnowledgeCandidate{}, KnowledgePackage{}, errors.New("knowledge candidate not found")
	}
	if candidate.Status != knowledgeCandidateReady {
		return KnowledgeCandidate{}, KnowledgePackage{}, errors.New("knowledge candidate is not ready for review")
	}
	validated := knowledgeCandidateForSnapshot(s.caseSnapshots[candidate.CaseID])
	if validated == nil || validated.Status != knowledgeCandidateReady || validated.ContentHash != candidate.ContentHash {
		return KnowledgeCandidate{}, KnowledgePackage{}, errors.New("knowledge candidate failed content-hash revalidation")
	}
	now := time.Now().UTC()
	actor, note := knowledgeActor(request.Actor), strings.TrimSpace(request.Note)
	payload := cloneCaseSnapshotPayload(candidate.Payload)
	payload["runtime_status"], payload["mirror_status"] = knowledgePackageShadow, "pending"
	pkg := &KnowledgePackage{PackageID: "KPK-" + candidate.CaseID, CandidateID: candidate.CandidateID, CaseID: candidate.CaseID, Status: knowledgePackageShadow, Payload: payload, PublishedAt: now, MirrorStatus: "pending", MirrorUpdatedAt: &now}
	hydrateKnowledgePackage(pkg)
	updated := cloneKnowledgeCandidate(candidate)
	updated.Payload["runtime_status"] = knowledgePackageShadow
	updated.Status, updated.PackageID, updated.DecidedAt, updated.DecidedBy, updated.DecisionNote, updated.UpdatedAt = knowledgeCandidateShadow, pkg.PackageID, &now, actor, note, now
	hydrateKnowledgeCandidate(&updated)
	event := s.newKnowledgeEventLocked(candidate.CandidateID, pkg.PackageID, "candidate_shadowed", actor, note, now)
	if !s.persistKnowledgeApprovalLocked(&updated, pkg, nil, event) {
		return KnowledgeCandidate{}, KnowledgePackage{}, errors.New("could not persist knowledge candidate shadow")
	}
	*candidate = updated
	s.knowledgePackages[pkg.PackageID] = pkg
	s.knowledgeEvents[event.EventID] = event
	return cloneKnowledgeCandidate(candidate), cloneKnowledgePackage(pkg), nil
}

// ActivateShadowKnowledgeCandidate makes an already validated shadow package
// visible to the Agent. It is the only shadow -> active transition.
func (s *Store) ActivateShadowKnowledgeCandidate(id string, request KnowledgeDecisionRequest) (KnowledgeCandidate, KnowledgePackage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := s.knowledgeCandidates[id]
	if candidate == nil {
		return KnowledgeCandidate{}, KnowledgePackage{}, errors.New("knowledge candidate not found")
	}
	if candidate.Status != knowledgeCandidateShadow {
		return KnowledgeCandidate{}, KnowledgePackage{}, errors.New("knowledge candidate is not in shadow")
	}
	pkg := s.knowledgePackages[candidate.PackageID]
	if pkg == nil || pkg.Status != knowledgePackageShadow {
		return KnowledgeCandidate{}, KnowledgePackage{}, errors.New("knowledge shadow package not found")
	}
	now := time.Now().UTC()
	actor, note := knowledgeActor(request.Actor), strings.TrimSpace(request.Note)
	var prior *KnowledgePackage
	for _, item := range s.knowledgePackages {
		if item == nil || item.Status != knowledgePackageActive || item.PackageID == pkg.PackageID {
			continue
		}
		if priorCandidate := s.knowledgeCandidates[item.CandidateID]; priorCandidate != nil && priorCandidate.KnowledgeFingerprint == candidate.KnowledgeFingerprint {
			prior = item
			break
		}
	}
	updatedCandidate, updatedPackage := cloneKnowledgeCandidate(candidate), cloneKnowledgePackage(pkg)
	updatedCandidate.Status, updatedCandidate.UpdatedAt, updatedCandidate.DecidedAt, updatedCandidate.DecidedBy, updatedCandidate.DecisionNote = knowledgeCandidateActive, now, &now, actor, note
	updatedCandidate.Payload["runtime_status"] = knowledgePackageActive
	updatedPackage.Status, updatedPackage.Payload["runtime_status"] = knowledgePackageActive, knowledgePackageActive
	hydrateKnowledgeCandidate(&updatedCandidate)
	hydrateKnowledgePackage(&updatedPackage)
	event := s.newKnowledgeEventLocked(candidate.CandidateID, pkg.PackageID, "shadow_activated", actor, note, now)
	if !s.persistKnowledgeActivationLocked(&updatedCandidate, &updatedPackage, prior, event) {
		return KnowledgeCandidate{}, KnowledgePackage{}, errors.New("could not persist knowledge shadow activation")
	}
	*candidate, *pkg = updatedCandidate, updatedPackage
	if prior != nil {
		prior.Status, prior.RetiredAt, prior.RetiredBy, prior.RetirementNote = knowledgePackageRetired, &now, actor, "superseded by "+candidate.CandidateID
		if priorCandidate := s.knowledgeCandidates[prior.CandidateID]; priorCandidate != nil {
			priorCandidate.Status, priorCandidate.UpdatedAt = knowledgeCandidateSuperseded, now
		}
	}
	s.knowledgeEvents[event.EventID] = event
	return cloneKnowledgeCandidate(candidate), cloneKnowledgePackage(pkg), nil
}

// RejectShadowKnowledgeCandidate retires an observation-only package without
// ever making it visible to the runtime.
func (s *Store) RejectShadowKnowledgeCandidate(id string, request KnowledgeDecisionRequest) (KnowledgeCandidate, KnowledgePackage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := s.knowledgeCandidates[id]
	if candidate == nil {
		return KnowledgeCandidate{}, KnowledgePackage{}, errors.New("knowledge candidate not found")
	}
	if candidate.Status != knowledgeCandidateShadow {
		return KnowledgeCandidate{}, KnowledgePackage{}, errors.New("knowledge candidate is not in shadow")
	}
	pkg := s.knowledgePackages[candidate.PackageID]
	if pkg == nil || pkg.Status != knowledgePackageShadow {
		return KnowledgeCandidate{}, KnowledgePackage{}, errors.New("knowledge shadow package not found")
	}
	now := time.Now().UTC()
	actor, note := knowledgeActor(request.Actor), strings.TrimSpace(request.Note)
	updatedCandidate, updatedPackage := cloneKnowledgeCandidate(candidate), cloneKnowledgePackage(pkg)
	updatedCandidate.Status, updatedCandidate.UpdatedAt, updatedCandidate.DecidedAt, updatedCandidate.DecidedBy, updatedCandidate.DecisionNote = knowledgeCandidateRejected, now, &now, actor, note
	updatedCandidate.Payload["runtime_status"] = knowledgePackageRetired
	updatedPackage.Status, updatedPackage.Payload["runtime_status"] = knowledgePackageRetired, knowledgePackageRetired
	updatedPackage.RetiredAt, updatedPackage.RetiredBy, updatedPackage.RetirementNote = &now, actor, note
	hydrateKnowledgeCandidate(&updatedCandidate)
	hydrateKnowledgePackage(&updatedPackage)
	event := s.newKnowledgeEventLocked(candidate.CandidateID, pkg.PackageID, "shadow_rejected", actor, note, now)
	if !s.persistKnowledgeShadowRejectionLocked(&updatedCandidate, &updatedPackage, event) {
		return KnowledgeCandidate{}, KnowledgePackage{}, errors.New("could not persist knowledge shadow rejection")
	}
	*candidate, *pkg = updatedCandidate, updatedPackage
	s.knowledgeEvents[event.EventID] = event
	return cloneKnowledgeCandidate(candidate), cloneKnowledgePackage(pkg), nil
}

func (s *Store) RejectKnowledgeCandidate(id string, request KnowledgeDecisionRequest) (KnowledgeCandidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := s.knowledgeCandidates[id]
	if candidate == nil {
		return KnowledgeCandidate{}, errors.New("knowledge candidate not found")
	}
	if candidate.Status != knowledgeCandidateReady {
		return KnowledgeCandidate{}, errors.New("knowledge candidate is not ready for review")
	}
	now := time.Now().UTC()
	actor, note := knowledgeActor(request.Actor), strings.TrimSpace(request.Note)
	updated := cloneKnowledgeCandidate(candidate)
	updated.Status, updated.DecidedAt, updated.DecidedBy, updated.DecisionNote, updated.UpdatedAt = knowledgeCandidateRejected, &now, actor, note, now
	event := s.newKnowledgeEventLocked(candidate.CandidateID, "", "candidate_rejected", actor, note, now)
	if !s.persistKnowledgeCandidateTransitionLocked(&updated, event) {
		return KnowledgeCandidate{}, errors.New("could not persist knowledge candidate rejection")
	}
	*candidate = updated
	s.knowledgeEvents[event.EventID] = event
	return cloneKnowledgeCandidate(candidate), nil
}

// FailKnowledgeCandidateValidation records an explicit Agent semantic
// rejection. Transport and 5xx failures never call this method, so a candidate
// remains ready when validation infrastructure is unavailable.
func (s *Store) FailKnowledgeCandidateValidation(id string) (KnowledgeCandidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := s.knowledgeCandidates[id]
	if candidate == nil {
		return KnowledgeCandidate{}, errors.New("knowledge candidate not found")
	}
	if candidate.Status != knowledgeCandidateReady {
		return KnowledgeCandidate{}, errors.New("knowledge candidate is not ready for review")
	}
	now := time.Now().UTC()
	updated := cloneKnowledgeCandidate(candidate)
	updated.Status, updated.ValidationError, updated.UpdatedAt = knowledgeCandidateValidationFailed, "agent semantic validation rejected compiled package", now
	event := s.newKnowledgeEventLocked(candidate.CandidateID, "", "candidate_validation_failed", "system", "agent semantic validation rejected", now)
	if !s.persistKnowledgeValidationFailureLocked(&updated, event) {
		return KnowledgeCandidate{}, errors.New("could not persist knowledge validation failure")
	}
	*candidate = updated
	s.knowledgeEvents[event.EventID] = event
	return cloneKnowledgeCandidate(candidate), nil
}

func (s *Store) RetireKnowledgePackage(id string, request KnowledgeDecisionRequest) (KnowledgePackage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pkg := s.knowledgePackages[id]
	if pkg == nil {
		return KnowledgePackage{}, errors.New("knowledge package not found")
	}
	if pkg.Status != knowledgePackageActive {
		return KnowledgePackage{}, errors.New("knowledge package is not active")
	}
	now := time.Now().UTC()
	actor, note := knowledgeActor(request.Actor), strings.TrimSpace(request.Note)
	updated := cloneKnowledgePackage(pkg)
	updated.Status, updated.RetiredAt, updated.RetiredBy, updated.RetirementNote = knowledgePackageRetired, &now, actor, note
	updated.Payload["runtime_status"] = knowledgePackageRetired
	hydrateKnowledgePackage(&updated)
	event := s.newKnowledgeEventLocked(pkg.CandidateID, pkg.PackageID, "package_retired", actor, note, now)
	if !s.persistKnowledgePackageRetirementLocked(&updated, event) {
		return KnowledgePackage{}, errors.New("could not persist knowledge package retirement")
	}
	*pkg = updated
	s.knowledgeEvents[event.EventID] = event
	return cloneKnowledgePackage(pkg), nil
}

// UpdateKnowledgePackageMirror records advisory TypeDB mirror progress. It is
// deliberately separate from runtime package activation: a mirror failure must
// never withdraw a locally validated active package.
func (s *Store) UpdateKnowledgePackageMirror(id, status, lastError string, updatedAt time.Time) (KnowledgePackage, error) {
	if status != "pending" && status != "synced" && status != "error" {
		return KnowledgePackage{}, errors.New("invalid knowledge mirror status")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pkg := s.knowledgePackages[id]
	if pkg == nil {
		return KnowledgePackage{}, errors.New("knowledge package not found")
	}
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	updated := cloneKnowledgePackage(pkg)
	updated.MirrorStatus, updated.MirrorLastError, updated.MirrorUpdatedAt = status, strings.TrimSpace(lastError), &updatedAt
	if !s.persistKnowledgeMirrorLocked(&updated) {
		return KnowledgePackage{}, errors.New("could not persist knowledge package mirror status")
	}
	*pkg = updated
	return cloneKnowledgePackage(pkg), nil
}

func (s *Store) newKnowledgeEventLocked(candidateID, packageID, eventType, actor, note string, now time.Time) *KnowledgeEvent {
	return &KnowledgeEvent{EventID: nextID("KNE", s.knowledgeEventSeq.Add(1)), CandidateID: candidateID, PackageID: packageID, Type: eventType, Actor: actor, Note: note, CreatedAt: now}
}

func knowledgeActor(actor string) string { return first(strings.TrimSpace(actor), "anonymous") }
