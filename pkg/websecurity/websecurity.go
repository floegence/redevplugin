package websecurity

import "net/http"

type OriginDecision string

const (
	OriginAllow OriginDecision = "allow"
	OriginDeny  OriginDecision = "deny"
)

type OriginRole string

const (
	OriginEnvTrusted    OriginRole = "env_trusted"
	OriginCodeSpace     OriginRole = "code_space"
	OriginPortForward   OriginRole = "port_forward"
	OriginPluginSandbox OriginRole = "plugin_sandbox"
	OriginUnknown       OriginRole = "unknown"
)

type RequestContext struct {
	Origin string     `json:"origin"`
	Role   OriginRole `json:"role"`
	Route  string     `json:"route"`
	Method string     `json:"method"`
}

type Guard interface {
	Evaluate(r *http.Request) (RequestContext, OriginDecision, error)
	ValidateCSRF(r *http.Request, sessionHash string) error
}
