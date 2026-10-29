package httpadapter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/floegence/redevplugin/v3/internal/controlstore"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/security"
)

func TestConnectionFailurePreservesSpecificStatus(t *testing.T) {
	h := Handler{host: newHTTPTestHost(t)}
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   security.ErrorCode
	}{
		{"unavailable", host.ErrConnectionUnavailable, http.StatusConflict, security.ErrConnectionUnavailable},
		{"wrapped unavailable", fmt.Errorf("review: %w", host.ErrConnectionUnavailable), http.StatusConflict, security.ErrConnectionUnavailable},
		{"target denied", connectivity.ErrTargetDenied, http.StatusForbidden, security.ErrNetworkTargetDenied},
		{"connector denied", connectivity.ErrConnectorDenied, http.StatusForbidden, security.ErrNetworkTargetDenied},
		{"stale revision", controlstore.ErrRevisionConflict, http.StatusConflict, security.ErrConnectionConflict},
		{"invalid connector", connectivity.ErrInvalidConnector, http.StatusBadRequest, security.ErrInvalidRequest},
	} {
		for _, mutates := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/mutates=%t", tc.name, mutates), func(t *testing.T) {
				w := httptest.NewRecorder()
				r := httptest.NewRequest(http.MethodPost, "https://host.example/connections", nil).WithContext(httpTestContext())
				h.connectionFailure(w, r, tc.err, mutates)
				var body struct {
					Error struct {
						Code security.ErrorCode `json:"code"`
					} `json:"error"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if w.Code != tc.status || body.Error.Code != tc.code {
					t.Fatalf("status=%d code=%s, want %d %s", w.Code, body.Error.Code, tc.status, tc.code)
				}
			})
		}
	}
}
