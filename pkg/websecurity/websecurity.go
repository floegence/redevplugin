package websecurity

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

type OriginDecision string

const (
	OriginTrustedParent OriginDecision = "trusted_parent"
	OriginDeny          OriginDecision = "deny"
)

var (
	ErrOriginDenied  = errors.New("request origin is denied")
	ErrCSRFRequired  = errors.New("csrf token is required")
	ErrCSRFInvalid   = errors.New("csrf token is invalid")
	ErrScopeRequired = errors.New("trusted request scope is required")
)

type RequestScope struct {
	OwnerSessionHash     string `json:"owner_session_hash"`
	OwnerUserHash        string `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string `json:"session_channel_id_hash"`
}

func (s RequestScope) Valid() bool {
	return strings.TrimSpace(s.OwnerSessionHash) != "" && strings.TrimSpace(s.SessionChannelIDHash) != ""
}

type RequestContext struct {
	Origin string       `json:"origin"`
	Route  string       `json:"route"`
	Method string       `json:"method"`
	Scope  RequestScope `json:"scope"`
}

type Guard interface {
	Evaluate(r *http.Request) (RequestContext, OriginDecision, error)
	ValidateCSRF(r *http.Request, sessionHash string) error
}

type requestContextKey struct{}

func WithRequestContext(ctx context.Context, requestContext RequestContext) context.Context {
	return context.WithValue(ctx, requestContextKey{}, requestContext)
}

func RequestContextFromContext(ctx context.Context) (RequestContext, bool) {
	requestContext, ok := ctx.Value(requestContextKey{}).(RequestContext)
	return requestContext, ok
}
