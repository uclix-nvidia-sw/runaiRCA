package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type operatorRoundTripper func(*http.Request) (*http.Response, error)

func (fn operatorRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func operatorCatalogAgent(t *testing.T, analyze func(*http.Request) AgentAnalysisResponse) *Server {
	t.Helper()
	server := NewServer()
	server.agentURL = "http://agent.test"
	server.client = &http.Client{Transport: operatorRoundTripper(func(r *http.Request) (*http.Response, error) {
		var body any
		status := http.StatusOK
		switch r.URL.Path {
		case "/knowledge/families":
			body = RootCauseFamilyCatalog{Families: []string{"gpu_hardware_error", "runai_scheduling_quota"}}
		case "/analyze":
			body = analyze(r)
		default:
			status = http.StatusNotFound
			body = map[string]string{"error": "unexpected agent path"}
		}
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(encoded))}, nil
	})}
	return server
}

func TestOperatorCorrectionAppendsPinsAndCanBeApproved(t *testing.T) {
	server := operatorCatalogAgent(t, func(_ *http.Request) AgentAnalysisResponse {
		return AgentAnalysisResponse{Status: "ok"}
	})
	incident, alert := seedAlert(t, server, "operator-correction-pinned")
	ai, created := server.store.CreateAnalysisRunIfAllowed("manual", "incident", incident.IncidentID, incident.IncidentID, alert.AlertID, "AI RCA", "")
	if !created {
		t.Fatal("expected initial AI run")
	}
	if _, ok := server.store.CompleteAnalysisRun(ai.RunID, AgentAnalysisResponse{AnalysisSummary: "AI conclusion", AnalysisDetail: "AI detail", RootCauseFamily: "runai_scheduling_quota", Context: map[string]any{"analysis_hash": "ai-hash"}}); !ok {
		t.Fatal("expected initial AI run to complete")
	}

	payload := []byte(`{"root_cause_family":"gpu_hardware_error","summary":"XID evidence identifies the GPU.","actions":["Drain the node","Replace the GPU"]}`)
	recorder := httptest.NewRecorder()
	server.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incident.IncidentID+"/rca-correction", bytes.NewReader(payload)))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create correction status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Data AnalysisRun `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode correction response: %v", err)
	}
	correction := body.Data
	if correction.RunID == ai.RunID || correction.Source != "operator" || correction.Status != "complete" || correction.Metadata["analysis_hash"] == "" || correction.Metadata["pinned"] != true {
		t.Fatalf("operator correction must append a pinned hash-bound run: %+v", correction)
	}
	if correction.Metadata["operator_correction"].(map[string]any)["base_run_id"] != ai.RunID {
		t.Fatalf("operator correction did not retain base run: %+v", correction.Metadata)
	}
	if got, ok := server.store.IncidentDetail(incident.IncidentID); !ok || got.AnalysisRunID != correction.RunID {
		t.Fatalf("pinned correction did not surface in incident detail: %+v ok=%t", got, ok)
	}

	time.Sleep(time.Millisecond)
	later, created := server.store.CreateAnalysisRunIfAllowed("auto", "incident", incident.IncidentID, incident.IncidentID, alert.AlertID, "Later AI RCA", "")
	if !created || later.RunID == correction.RunID {
		t.Fatalf("later AI run was not appended: %+v created=%t", later, created)
	}
	if _, ok := server.store.CompleteAnalysisRun(later.RunID, AgentAnalysisResponse{AnalysisSummary: "Later AI conclusion", AnalysisDetail: "Later AI detail", RootCauseFamily: "runai_scheduling_quota", Context: map[string]any{"analysis_hash": "later-hash"}}); !ok {
		t.Fatal("expected later AI run to complete")
	}
	if got, _ := server.store.IncidentDetail(incident.IncidentID); got.AnalysisRunID != correction.RunID {
		t.Fatalf("pinned correction lost to newer AI run: %+v", got)
	}

	recorder = httptest.NewRecorder()
	server.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incident.IncidentID+"/rca-pin", bytes.NewBufferString(`{"pinned":false}`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("unpin status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got, _ := server.store.IncidentDetail(incident.IncidentID); got.AnalysisRunID != later.RunID {
		t.Fatalf("unpin did not restore newest AI run: %+v", got)
	}

	// Pin again before approval so the correction is the current RCA snapshot.
	if _, ok := server.store.SetLatestOperatorRunPinned(incident.IncidentID, true); !ok {
		t.Fatal("expected operator correction to repin")
	}
	recorder = httptest.NewRecorder()
	server.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incident.IncidentID+"/resolve", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("approve correction status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	snapshot, ok := server.store.ApprovedCaseSnapshot(incident.IncidentID)
	if !ok || snapshot.RunID != correction.RunID || snapshot.AnalysisHash != correction.Metadata["analysis_hash"] {
		t.Fatalf("approval did not create correction snapshot: %+v ok=%t", snapshot, ok)
	}
}

func TestOperatorCorrectionRejectsInvalidFamilyAndEmptySummary(t *testing.T) {
	server := operatorCatalogAgent(t, func(_ *http.Request) AgentAnalysisResponse {
		return AgentAnalysisResponse{Status: "ok"}
	})
	incident, _ := seedAlert(t, server, "operator-correction-validation")
	for _, payload := range []string{
		`{"root_cause_family":"gpu_hardware_error","summary":"  "}`,
		`{"root_cause_family":"made_up_family","summary":"A conclusion"}`,
	} {
		recorder := httptest.NewRecorder()
		server.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incident.IncidentID+"/rca-correction", bytes.NewBufferString(payload)))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("invalid correction %s status=%d body=%s", payload, recorder.Code, recorder.Body.String())
		}
	}
}

func TestPinnedOperatorCorrectionMakesFeedbackReanalysisAppend(t *testing.T) {
	store := NewStore()
	incident, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "operator-correction-reuse"}, Alert{Status: "firing", Labels: map[string]string{"alertname": "RunAIQueueBlocked"}, Fingerprint: "operator-correction-reuse"})
	ai, created := store.CreateAnalysisRunIfAllowed("manual", "incident", incident.IncidentID, incident.IncidentID, alert.AlertID, "AI RCA", "")
	if !created {
		t.Fatal("expected initial AI run")
	}
	if _, ok := store.CompleteAnalysisRun(ai.RunID, AgentAnalysisResponse{AnalysisSummary: "AI RCA"}); !ok {
		t.Fatal("expected initial AI completion")
	}
	correction, ok := store.CreateOperatorRun(incident.IncidentID, alert.AlertID, ai.RunID, "gpu_hardware_error", "Operator correction", "## 2. 원인")
	if !ok {
		t.Fatal("expected pinned correction")
	}
	feedback, created := store.CreateAnalysisRunIfAllowed("feedback", "incident", incident.IncidentID, incident.IncidentID, alert.AlertID, "Feedback", "recheck")
	if !created || feedback.RunID == correction.RunID || feedback.RunID == ai.RunID {
		t.Fatalf("feedback reanalysis must append after correction: %+v created=%t", feedback, created)
	}
	if runs := store.ListAnalysisRuns(); len(runs) != 3 {
		t.Fatalf("feedback reanalysis rewrote an existing run: %+v", runs)
	}
}

func TestReverifySendsPinnedOperatorFamilyToAgent(t *testing.T) {
	received := make(chan AgentAnalysisRequest, 1)
	server := operatorCatalogAgent(t, func(r *http.Request) AgentAnalysisResponse {
		var req AgentAnalysisRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode reverify request: %v", err)
		}
		received <- req
		return AgentAnalysisResponse{Status: "ok", AnalysisSummary: "Reverified", AnalysisDetail: "detail", RootCauseFamily: "gpu_hardware_error", Context: map[string]any{"analysis_hash": "reverify-hash"}}
	})
	incident, alert := seedAlert(t, server, "operator-correction-reverify")
	if _, ok := server.store.CreateOperatorRun(incident.IncidentID, alert.AlertID, "ANL-base", "gpu_hardware_error", "GPU XID", "## 2. 원인"); !ok {
		t.Fatal("expected pinned correction")
	}
	recorder := httptest.NewRecorder()
	server.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incident.IncidentID+"/reverify", nil))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("reverify status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	run := waitForRunStatus(t, server, "reverify", "complete")
	if run.Source != "reverify" {
		t.Fatalf("unexpected reverify run: %+v", run)
	}
	select {
	case req := <-received:
		if req.SeedFamily != "gpu_hardware_error" || req.AnalysisType != "reverify" {
			t.Fatalf("reverify agent request missing seed: %+v", req)
		}
	case <-time.After(time.Second):
		t.Fatal("agent did not receive reverify request")
	}
}
