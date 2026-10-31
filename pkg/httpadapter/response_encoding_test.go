package httpadapter

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/security"
)

func TestWriteJSONPreservesCanonicalEnvelopeBytes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		payload any
	}{
		{"success", http.StatusOK, successResponse{OK: true, Data: map[string]any{"text": "<script>&\u2028\u2029", "nested": map[string]any{"value": 1}}}},
		{"query error", http.StatusBadRequest, errorResponse{Code: security.ErrInvalidRequest, Message: "<invalid> & input"}},
		{"mutation error", http.StatusBadRequest, mutationErrorResponse{Code: security.ErrInvalidRequest, Message: "<invalid> & input", MutationOutcome: mutation.OutcomeNotCommitted}},
		{"typed details", http.StatusBadRequest, errorResponse{Code: security.ErrJSONLimitExceeded, Message: "payload too large", Details: errorDetails{Reason: string(jsonLimitReasonPayloadBytes)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expected, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			writeJSON(w, tc.status, tc.payload)
			if w.Code != tc.status || !bytes.Equal(w.Body.Bytes(), append(expected, '\n')) {
				t.Fatalf("status=%d body=%s want=%s", w.Code, w.Body.Bytes(), expected)
			}
			if w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("headers=%v", w.Header())
			}
		})
	}
}

func BenchmarkAuthenticatedRouteInvalidRequest(b *testing.B) {
	request, err := http.NewRequest(http.MethodPost, routeAuthorizationOrigin+"/_redevplugin/api/plugins/enable", http.NoBody)
	if err != nil {
		b.Fatal(err)
	}
	request.Header.Set("Authorization", routeAuthorizationBearer)
	request.Header.Set("Origin", routeAuthorizationOrigin)
	request.Header.Set("X-ReDevPlugin-CSRF", routeAuthorizationCSRF)
	request.Header.Set("Content-Type", "application/json")
	// The measured request stops at the required-revision check after all guards.
	handler, err := NewHandler(Dependencies{Host: &host.Host{}, Guard: routeAuthorizationPerformanceGuard{}})
	if err != nil {
		b.Fatal(err)
	}
	body := []byte("{}")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		isolated := *request
		isolated.Body = io.NopCloser(bytes.NewReader(body))
		isolated.ContentLength = int64(len(body))
		w := routeAuthorizationResponseWriter{header: make(http.Header)}
		handler.ServeHTTP(&w, &isolated)
		if w.status != http.StatusBadRequest {
			b.Fatalf("status=%d", w.status)
		}
	}
}

func TestWriteJSONKeepsEncodingFailuresClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload any
		outcome string
	}{
		{"invalid success", successResponse{Data: map[string]any{}}, "unknown"},
		{"unencodable success", successResponse{OK: true, Data: make(chan int)}, "unknown"},
		{"unknown error", errorResponse{Code: security.ErrorCode("UNKNOWN"), Message: "bad"}, ""},
		{"mismatched details", errorResponse{Code: security.ErrManagementRevisionMismatch, Message: "bad"}, ""},
		{"invalid outcome", mutationErrorResponse{Code: security.ErrInvalidRequest, Message: "bad", MutationOutcome: mutation.Outcome("invalid")}, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := http.StatusBadRequest
			if _, ok := tc.payload.(successResponse); ok {
				status = http.StatusOK
			}
			w := httptest.NewRecorder()
			writeJSON(w, status, tc.payload)
			var result struct {
				OK    bool
				Error struct {
					Code            string
					MutationOutcome string `json:"mutation_outcome"`
				}
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusInternalServerError || result.OK || result.Error.Code != string(security.ErrContractMismatch) || result.Error.MutationOutcome != tc.outcome {
				t.Fatalf("status=%d result=%+v", w.Code, result)
			}
		})
	}
}
