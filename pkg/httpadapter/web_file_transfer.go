package httpadapter

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
)

func serveWebFileTransfer(platform *host.Host, w http.ResponseWriter, r *http.Request, session host.WebSurfaceRequest, private bool) {
	if r.Method != http.MethodPost || r.Header.Get("Origin") != session.Origin || r.Header.Get("Sec-Fetch-Site") != "same-origin" || r.Header.Get("Sec-Fetch-Dest") != "empty" || (r.Header.Get("Sec-Fetch-Mode") != "cors" && r.Header.Get("Sec-Fetch-Mode") != "same-origin") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	request := host.WebFileTransferRequest{WebSurfaceRequest: session, Handle: r.URL.Query().Get("handle")}
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(5 * time.Minute))
	_ = controller.SetWriteDeadline(time.Now().Add(5 * time.Minute))
	transfer := func(source io.Reader, destination io.Writer) (int64, error) {
		if private {
			return platform.TransferWebPrivateFile(r.Context(), host.WebPrivateFileRequest{WebSurfaceRequest: session, StoreID: r.URL.Query().Get("store_id"), Path: r.URL.Query().Get("path")}, source, destination)
		}
		return platform.TransferWebFile(r.Context(), request, source, destination)
	}
	switch r.URL.Query().Get("direction") {
	case "read":
		w.Header().Set("Content-Type", "application/octet-stream")
		if _, err := transfer(nil, &webTransferWriter{webConnectionWriter{ResponseWriter: w}}); err != nil {
			panic(http.ErrAbortHandler)
		}
	case "write":
		count, err := transfer(r.Body, nil)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			code, retryable := host.WebResourceError(err)
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": map[string]any{"code": code, "retryable": retryable, "mutation_outcome": mutation.ForError(err)}, "count": count})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": count})
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

// Closing an output unblocks a slow client when its Surface is revoked.
type webTransferWriter struct{ webConnectionWriter }

func (w *webTransferWriter) Close() error {
	return http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now())
}
