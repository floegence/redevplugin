package httpadapter

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/websecurity"
)

const (
	conformanceTrustedOrigin = "https://trusted-host.example"
	conformanceCSRFToken     = "route-matrix-csrf-token"
	conformanceCSRFHeader    = "X-ReDevPlugin-CSRF"
)

func TestHandlerWebSecurityConformanceCoversEveryRoute(t *testing.T) {
	testCases := []struct {
		name      string
		configure func(*http.Request)
		wantCode  security.ErrorCode
		wantStage string
	}{
		{
			name:      "missing origin",
			configure: setConformanceCSRF,
			wantCode:  security.ErrOriginDenied,
			wantStage: "origin",
		},
		{
			name: "foreign origin",
			configure: func(r *http.Request) {
				r.Header.Set("Origin", "https://untrusted.example")
				setConformanceCSRF(r)
			},
			wantCode:  security.ErrOriginDenied,
			wantStage: "origin",
		},
		{
			name: "null origin",
			configure: func(r *http.Request) {
				r.Header.Set("Origin", "null")
				setConformanceCSRF(r)
			},
			wantCode:  security.ErrOriginDenied,
			wantStage: "origin",
		},
		{
			name: "duplicate origin",
			configure: func(r *http.Request) {
				r.Header.Add("Origin", conformanceTrustedOrigin)
				r.Header.Add("Origin", conformanceTrustedOrigin)
				setConformanceCSRF(r)
			},
			wantCode:  security.ErrOriginDenied,
			wantStage: "origin",
		},
		{
			name: "origin with surrounding whitespace",
			configure: func(r *http.Request) {
				r.Header.Set("Origin", " "+conformanceTrustedOrigin+" ")
				setConformanceCSRF(r)
			},
			wantCode:  security.ErrOriginDenied,
			wantStage: "origin",
		},
		{
			name: "missing csrf",
			configure: func(r *http.Request) {
				r.Header.Set("Origin", conformanceTrustedOrigin)
			},
			wantCode:  security.ErrCSRFRequired,
			wantStage: "csrf",
		},
		{
			name: "invalid csrf",
			configure: func(r *http.Request) {
				r.Header.Set("Origin", conformanceTrustedOrigin)
				r.Header.Set(conformanceCSRFHeader, "invalid-token")
			},
			wantCode:  security.ErrCSRFInvalid,
			wantStage: "csrf",
		},
		{
			name: "duplicate csrf",
			configure: func(r *http.Request) {
				r.Header.Set("Origin", conformanceTrustedOrigin)
				r.Header.Add(conformanceCSRFHeader, conformanceCSRFToken)
				r.Header.Add(conformanceCSRFHeader, conformanceCSRFToken)
			},
			wantCode:  security.ErrCSRFInvalid,
			wantStage: "csrf",
		},
		{
			name: "csrf with surrounding whitespace",
			configure: func(r *http.Request) {
				r.Header.Set("Origin", conformanceTrustedOrigin)
				r.Header.Set(conformanceCSRFHeader, " "+conformanceCSRFToken+" ")
			},
			wantCode:  security.ErrCSRFInvalid,
			wantStage: "csrf",
		},
	}

	sawAssetRead := false
	sawStreamRead := false
	for _, route := range routes {
		route := route
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			if route.action == websecurity.RouteActionReadSurfaceAsset {
				sawAssetRead = true
			}
			if route.action == websecurity.RouteActionReadSurfaceStream {
				sawStreamRead = true
			}
			for _, testCase := range testCases {
				testCase := testCase
				t.Run(testCase.name, func(t *testing.T) {
					guard := &routeSecurityConformanceGuard{}
					handler := mustNewHandler(t, newHTTPTestHost(t), guard)
					req := newRouteSecurityConformanceRequest(route)
					testCase.configure(req)
					rec := httptest.NewRecorder()

					handler.ServeHTTP(rec, req)

					assertConformanceError(t, rec, testCase.wantCode)
					switch testCase.wantStage {
					case "origin":
						assertConformanceGuardCalls(t, guard, 1, 1, 0, 0)
					case "csrf":
						assertConformanceGuardCalls(t, guard, 1, 1, 1, 0)
					default:
						t.Fatalf("unknown conformance stage %q", testCase.wantStage)
					}
				})
			}
		})
	}
	if !sawAssetRead || !sawStreamRead {
		t.Fatalf("route matrix missing unsafe read routes: asset=%t stream=%t", sawAssetRead, sawStreamRead)
	}
}

func TestHandlerWebSecurityConformanceDeniesEveryClosedRouteAction(t *testing.T) {
	for _, route := range routes {
		route := route
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			guard := &routeSecurityConformanceGuard{denyAction: true}
			handler := mustNewHandler(t, newHTTPTestHost(t), guard)
			req := newRouteSecurityConformanceRequest(route)
			req.Header.Set("Origin", conformanceTrustedOrigin)
			setConformanceCSRF(req)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assertConformanceError(t, rec, security.ErrActionDenied)
			assertConformanceGuardCalls(t, guard, 1, 1, 1, 1)
			if guard.lastAction != route.action || !guard.lastAction.Valid() || guard.lastEffect != route.Effect {
				t.Fatalf("denied route = {%q %q}, want {%q %q}", guard.lastAction, guard.lastEffect, route.action, route.Effect)
			}
		})
	}
}

func TestRouteSecurityContractRejectsUnknownAction(t *testing.T) {
	route := routes[0]
	route.action = websecurity.RouteAction("plugin.unknown")
	if err := route.validate(); !errors.Is(err, websecurity.ErrRouteActionInvalid) {
		t.Fatalf("route.validate() error = %v, want %v", err, websecurity.ErrRouteActionInvalid)
	}
}

func TestRouteSecurityContractRejectsUnknownEffect(t *testing.T) {
	route := routes[0]
	route.Effect = websecurity.RouteEffect("unknown")
	if err := route.validate(); !errors.Is(err, websecurity.ErrRouteEffectInvalid) {
		t.Fatalf("route.validate() error = %v, want %v", err, websecurity.ErrRouteEffectInvalid)
	}
}

func TestRouteSecurityContractRejectsMethodsOutsideEachEffect(t *testing.T) {
	tests := []struct {
		name   string
		effect websecurity.RouteEffect
		method string
	}{
		{name: "query get", effect: websecurity.RouteEffectQuery, method: http.MethodGet},
		{name: "mutation get", effect: websecurity.RouteEffectMutation, method: http.MethodGet},
		{name: "mutation head", effect: websecurity.RouteEffectMutation, method: http.MethodHead},
		{name: "mutation options", effect: websecurity.RouteEffectMutation, method: http.MethodOptions},
		{name: "mutation custom", effect: websecurity.RouteEffectMutation, method: "INVOKE"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			route := routes[0]
			route.Effect = testCase.effect
			route.Method = testCase.method
			if err := route.validate(); err == nil {
				t.Fatalf("route.validate() accepted %s method %s", testCase.effect, testCase.method)
			}
		})
	}
}

func TestHandlerWebSecurityConfigurationFailsClosedAtInitialization(t *testing.T) {
	var typedNilHost *host.Host
	var typedNilGuard *routeSecurityConformanceGuard
	tests := []struct {
		name        string
		deps        Dependencies
		wantAdapter string
	}{
		{
			name:        "typed nil host",
			deps:        Dependencies{Host: typedNilHost, Guard: &routeSecurityConformanceGuard{}},
			wantAdapter: "host",
		},
		{
			name:        "typed nil guard",
			deps:        Dependencies{Host: newHTTPTestHost(t), Guard: typedNilGuard},
			wantAdapter: "web security guard",
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			handler, err := NewHandler(testCase.deps)
			if handler != nil {
				t.Fatalf("NewHandler() handler = %#v, want nil", handler)
			}
			var configErr *host.HostConfigError
			if !errors.As(err, &configErr) || !errors.Is(err, host.ErrHostConfig) {
				t.Fatalf("NewHandler() error = %v, want HostConfigError", err)
			}
			if configErr.Module != "http" || configErr.Adapter != testCase.wantAdapter {
				t.Fatalf("HostConfigError = %#v, want module http adapter %q", configErr, testCase.wantAdapter)
			}
		})
	}
}

type routeSecurityConformanceGuard struct {
	denyAction        bool
	authenticateCount int
	originCount       int
	csrfCount         int
	authorizeCount    int
	lastAction        websecurity.RouteAction
	lastEffect        websecurity.RouteEffect
}

func (g *routeSecurityConformanceGuard) Authenticate(*http.Request) (sessionctx.Context, error) {
	g.authenticateCount++
	return sessionctx.Context{
		OwnerSessionHash:     "conformance_session_hash",
		OwnerUserHash:        "conformance_user_hash",
		OwnerEnvHash:         "conformance_env_hash",
		SessionChannelIDHash: "conformance_channel_hash",
	}, nil
}

func (g *routeSecurityConformanceGuard) ValidateOrigin(r *http.Request, _ sessionctx.Context, policy websecurity.OriginPolicy) error {
	g.originCount++
	if policy != websecurity.OriginPolicyTrustedHost {
		return websecurity.ErrOriginPolicyInvalid
	}
	values := r.Header.Values("Origin")
	if len(values) != 1 || values[0] != conformanceTrustedOrigin || strings.Contains(values[0], ",") {
		return websecurity.ErrOriginDenied
	}
	return nil
}

func (g *routeSecurityConformanceGuard) ValidateCSRF(r *http.Request, _ sessionctx.Context, policy websecurity.CSRFPolicy) error {
	g.csrfCount++
	if !policy.Valid() {
		return websecurity.ErrCSRFPolicyInvalid
	}
	if policy == websecurity.CSRFPolicyNotRequired {
		return nil
	}
	values := r.Header.Values(conformanceCSRFHeader)
	if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
		return websecurity.ErrCSRFRequired
	}
	if len(values) != 1 || subtle.ConstantTimeCompare([]byte(values[0]), []byte(conformanceCSRFToken)) != 1 {
		return websecurity.ErrCSRFInvalid
	}
	return nil
}

func (g *routeSecurityConformanceGuard) AuthorizeRoute(_ *http.Request, _ sessionctx.Context, action websecurity.RouteAction, effect websecurity.RouteEffect) error {
	g.authorizeCount++
	g.lastAction = action
	g.lastEffect = effect
	if !action.Valid() {
		return websecurity.ErrRouteActionInvalid
	}
	if !effect.Valid() {
		return websecurity.ErrRouteEffectInvalid
	}
	if g.denyAction {
		return errors.New("route action denied")
	}
	return nil
}

func newRouteSecurityConformanceRequest(route routeSpec) *http.Request {
	body := bytes.NewReader(nil)
	if route.Method != http.MethodGet && route.Method != http.MethodHead && route.Method != http.MethodOptions {
		body = bytes.NewReader([]byte(`{}`))
	}
	req := httptest.NewRequest(route.Method, samplePathForRoute(route.Path), body)
	if route.Method != http.MethodGet && route.Method != http.MethodHead && route.Method != http.MethodOptions {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func setConformanceCSRF(r *http.Request) {
	r.Header.Set(conformanceCSRFHeader, conformanceCSRFToken)
}

func assertConformanceGuardCalls(t *testing.T, guard *routeSecurityConformanceGuard, authenticate, origin, csrf, authorize int) {
	t.Helper()
	if guard.authenticateCount != authenticate || guard.originCount != origin || guard.csrfCount != csrf || guard.authorizeCount != authorize {
		t.Fatalf(
			"guard calls = authenticate:%d origin:%d csrf:%d authorize:%d, want authenticate:%d origin:%d csrf:%d authorize:%d",
			guard.authenticateCount,
			guard.originCount,
			guard.csrfCount,
			guard.authorizeCount,
			authenticate,
			origin,
			csrf,
			authorize,
		)
	}
}

func assertConformanceError(t *testing.T, rec *httptest.ResponseRecorder, wantCode security.ErrorCode) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	var envelope decodedErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.Code != string(wantCode) {
		t.Fatalf("error envelope = %#v, want code %q", envelope, wantCode)
	}
}
