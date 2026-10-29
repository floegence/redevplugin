package httpadapter

import (
	"encoding/json"
	"errors"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/floegence/redevplugin/v3/pkg/host"
)

func serveWebConnection(platform *host.Host, w http.ResponseWriter, r *http.Request, session host.WebSurfaceRequest, route string) {
	// Fetch Metadata is browser-authored. Remote data cannot become a document,
	// script, worker, stylesheet or image on the privileged application origin.
	if r.Header.Get("Sec-Fetch-Dest") != "empty" || r.Header.Get("Sec-Fetch-Site") != "same-origin" || (r.Header.Get("Sec-Fetch-Mode") != "cors" && r.Header.Get("Sec-Fetch-Mode") != "same-origin") || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != session.Origin) {
		http.Error(w, "Application connection context denied", http.StatusForbidden)
		return
	}
	if route == "connection" {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		index := 0
		if value := r.URL.Query().Get("destination_index"); value != "" {
			var err error
			index, err = strconv.Atoi(value)
			if err != nil || index < 0 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		connection, err := platform.GetWebConnection(r.Context(), host.WebConnectionRequest{WebSurfaceRequest: session, ConnectorID: r.URL.Query().Get("connector_id"), DestinationIndex: index})
		if err != nil {
			http.Error(w, "Connection unavailable; review its configuration and permissions", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"connector_id": connection.ConnectorID, "connection_id": connection.ConnectionID, "base_path": connection.BasePath, "http_methods": connection.HTTPMethods})
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(route, "connections/"), "/", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	prefix := host.WebSurfacePlatformPath + "connections/" + parts[0] + "/" + parts[1] + "/"
	escaped := r.URL.EscapedPath()
	if !strings.HasPrefix(escaped, prefix) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	path := "/" + strings.TrimPrefix(escaped, prefix)
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		path += "?" + r.URL.RawQuery
	}
	index := 0
	if strings.HasPrefix(parts[1], "fixed-") {
		var err error
		index, err = strconv.Atoi(strings.TrimPrefix(parts[1], "fixed-"))
		if err != nil || index < 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	headers := make(http.Header)
	for name, values := range r.Header {
		if webConnectionRequestHeader(name) {
			headers[name] = append([]string(nil), values...)
		}
	}
	response, err := platform.OpenWebConnectionHTTP(r.Context(), host.WebConnectionHTTPRequest{WebConnectionRequest: host.WebConnectionRequest{WebSurfaceRequest: session, ConnectorID: parts[0], DestinationIndex: index}, ConnectionID: parts[1], Method: r.Method, RequestURI: path, Headers: headers, Body: r.Body})
	if err != nil {
		// No retry or redirect is performed, including writes with an unknown result.
		status := http.StatusBadGateway
		if errors.Is(err, host.ErrConnectionUnavailable) {
			status = http.StatusConflict
		} else if errors.Is(err, os.ErrPermission) || errors.Is(err, permissions.ErrPermissionDenied) || errors.Is(err, connectivity.ErrConnectorDenied) || errors.Is(err, connectivity.ErrTargetDenied) {
			status = http.StatusForbidden
		} else if errors.Is(err, connectivity.ErrInvalidConnector) {
			status = http.StatusBadRequest
		}
		http.Error(w, "Connection request failed", status)
		return
	}
	defer response.Body.Close()
	for _, name := range []string{"Content-Type", "Content-Length", "Content-Encoding", "Content-Language", "ETag", "Last-Modified", "Accept-Ranges", "Content-Range", "Retry-After"} {
		if values := response.Header.Values(name); len(values) > 0 {
			w.Header()[name] = append([]string(nil), values...)
		}
	}
	w.WriteHeader(response.StatusCode)
	if r.Method == http.MethodHead {
		return
	}
	writer := &webConnectionWriter{ResponseWriter: w}
	if _, err := io.Copy(writer, response.Body); err != nil && !errors.Is(err, io.EOF) {
		// Terminate an incomplete response so native fetch rejects a truncated stream.
		panic(http.ErrAbortHandler)
	}
}
func webConnectionRequestHeader(name string) bool {
	name = strings.ToLower(name)
	if strings.HasPrefix(name, "sec-") || strings.HasPrefix(name, "proxy-") || strings.HasPrefix(name, "x-forwarded-") {
		return false
	}
	switch name {
	case "cookie", "host", "origin", "referer", "connection", "upgrade", "content-length", "transfer-encoding", "te", "trailer", "keep-alive", "forwarded", "accept-encoding", "alt-svc", "http2-settings":
		return false
	default:
		return true
	}
}

type webConnectionWriter struct{ http.ResponseWriter }

func (w *webConnectionWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if err == nil {
		err = http.NewResponseController(w.ResponseWriter).Flush()
		if errors.Is(err, http.ErrNotSupported) {
			err = nil
		}
	}
	return n, err
}
