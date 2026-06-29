package httpadapter

import (
	"encoding/json"
	"net/http"
	"sort"
)

type Envelope struct {
	OK        bool   `json:"ok"`
	Data      any    `json:"data,omitempty"`
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

type Route struct {
	Method string
	Path   string
}

func RouteSet() []Route {
	routes := []Route{
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/install"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/enable"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/disable"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/uninstall"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/update"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/downgrade"},
		{Method: http.MethodGet, Path: "/_redeven_proxy/api/plugins/catalog"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/surfaces/bootstrap"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/rpc"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/confirm"},
		{Method: http.MethodGet, Path: "/_redeven_proxy/api/plugins/operations"},
		{Method: http.MethodGet, Path: "/_redeven_proxy/api/plugins/operations/{operation_id}"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/operations/{operation_id}/cancel"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/data/export"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/data/import"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/secrets/bind"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/secrets/test"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/secrets/delete"},
		{Method: http.MethodPost, Path: "/_redeven_plugin/bootstrap"},
		{Method: http.MethodGet, Path: "/_redeven_plugin/assets/{asset_path...}"},
		{Method: http.MethodGet, Path: "/_redeven_plugin/stream/{stream_id}"},
		{Method: http.MethodPost, Path: "/_redeven_plugin/csp-report"},
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path == routes[j].Path {
			return routes[i].Method < routes[j].Method
		}
		return routes[i].Path < routes[j].Path
	})
	return routes
}

func WriteJSON(w http.ResponseWriter, status int, envelope Envelope) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope)
}
