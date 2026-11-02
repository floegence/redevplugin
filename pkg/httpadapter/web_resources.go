package httpadapter

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
)

func serveWebResource(platform *host.Host, w http.ResponseWriter, r *http.Request, session host.WebSurfaceRequest) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Origin") != session.Origin || r.Header.Get("Sec-Fetch-Site") != "same-origin" || r.Header.Get("Sec-Fetch-Dest") != "empty" || (r.Header.Get("Sec-Fetch-Mode") != "cors" && r.Header.Get("Sec-Fetch-Mode") != "same-origin") || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var input struct {
		Resource  string          `json:"resource"`
		Arguments json.RawMessage `json:"arguments"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 100<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	result, err := platform.WebResource(r.Context(), host.WebResourceRequest{WebSurfaceRequest: session, Resource: input.Resource, Arguments: input.Arguments})
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		code, retryable := host.WebResourceError(err)
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": map[string]any{"code": code, "retryable": retryable, "mutation_outcome": mutation.ForError(err)}})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": result})
}
