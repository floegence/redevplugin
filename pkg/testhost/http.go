package testhost

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/websecurity"
)

const csrfHeader = "X-ReDevPlugin-CSRF"

func validateParentOrigin(origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || u.Hostname() != "localhost" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("testhost requires an exact http://localhost:<port> origin")
	}
	port := u.Port()
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || u.Host != "localhost:"+port {
		return "", errors.New("testhost requires a canonical nonzero listener port")
	}
	return port, nil
}

type loopbackOrigins struct{ origin, port string }

func (o loopbackOrigins) AllocateSurfaceOrigin(_ context.Context, request host.SurfaceOriginRequest) (host.SurfaceOrigin, error) {
	return host.SurfaceOrigin{Origin: "http://" + request.OriginKey + ".localhost:" + o.port, ParentOrigin: o.origin}, nil
}
func (o loopbackOrigins) resolve(r *http.Request) (string, error) {
	name, port, err := net.SplitHostPort(r.Host)
	key := strings.TrimSuffix(name, ".localhost")
	if err != nil || port != o.port || name == key || len(key) != 48 || strings.Trim(key, "0123456789abcdef") != "" {
		return "", fmt.Errorf("invalid local application origin")
	}
	return "http://" + r.Host, nil
}

// Handler mounts the production API on the exact parent and the production Web
// resource handler on child origins. Parent is optional test-page content; it
// can never override platform routes or be reached through a child Host header.
func (h *Harness) Handler(parent http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if h.closed.Load() || h.platformHTTP == nil {
			http.Error(w, "test host unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Host != "localhost:"+h.port {
			h.childHTTP.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/_redevplugin/api/plugins/") {
			h.platformHTTP.ServeHTTP(w, r)
			return
		}
		if parent != nil {
			parent.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

// SessionHandler exchanges BrowserToken for an HttpOnly host-only cookie. The
// caller chooses its test-page route; this is not a production platform API.
func (h *Harness) SessionHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.closed.Load() || h.origin == "" {
			http.Error(w, "test host unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodPost || r.Host != "localhost:"+h.port || singleHeader(r, "Origin") != h.origin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 129))
		if err != nil || subtle.ConstantTimeCompare(raw, []byte(h.token)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		http.SetCookie(w, &http.Cookie{Name: h.cookieName, Value: h.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		w.WriteHeader(http.StatusNoContent)
	})
}

// NewRequest attaches test credentials only to this instance's parent origin.
// It does not perform a request or follow redirects.
func (h *Harness) NewRequest(ctx context.Context, method, target string, body io.Reader) (*http.Request, error) {
	if h.closed.Load() || h.origin == "" {
		return nil, errors.New("test host HTTP is unavailable")
	}
	u, err := url.Parse(target)
	if err != nil || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("invalid test request URL")
	}
	if u.IsAbs() {
		if u.Scheme+"://"+u.Host != h.origin {
			return nil, errors.New("test credentials cannot cross origins")
		}
	} else {
		if u.Host != "" || !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
			return nil, errors.New("test request requires a parent-relative path")
		}
		target = h.origin + target
	}
	r, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Origin", h.origin)
	r.Header.Set(csrfHeader, h.csrf)
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: h.cookieName, Value: h.token})
	return r, nil
}

type testGuard struct{ h *Harness }

func (g testGuard) Authenticate(r *http.Request) (sessionctx.Context, error) {
	if g.h.closed.Load() || g.h.origin == "" || r.Host != "localhost:"+g.h.port {
		return sessionctx.Context{}, host.ErrActionDenied
	}
	count := 0
	valid := false
	for _, cookie := range r.Cookies() {
		if cookie.Name == g.h.cookieName {
			count++
			valid = subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(g.h.token)) == 1
		}
	}
	if count != 1 || !valid {
		return sessionctx.Context{}, host.ErrActionDenied
	}
	return g.h.session, nil
}
func (g testGuard) ValidateOrigin(r *http.Request, s sessionctx.Context, p websecurity.OriginPolicy) error {
	if p != websecurity.OriginPolicyTrustedHost {
		return websecurity.ErrOriginPolicyInvalid
	}
	if !g.h.accepts(s) || singleHeader(r, "Origin") != g.h.origin || g.h.origin == "" {
		return websecurity.ErrOriginDenied
	}
	return nil
}
func (g testGuard) ValidateCSRF(r *http.Request, s sessionctx.Context, p websecurity.CSRFPolicy) error {
	if p != websecurity.CSRFPolicyRequired {
		return websecurity.ErrCSRFPolicyInvalid
	}
	value := singleHeader(r, csrfHeader)
	if value == "" {
		return websecurity.ErrCSRFRequired
	}
	if !g.h.accepts(s) || subtle.ConstantTimeCompare([]byte(value), []byte(g.h.csrf)) != 1 {
		return websecurity.ErrCSRFInvalid
	}
	return nil
}
func (g testGuard) AuthorizeRoute(_ *http.Request, s sessionctx.Context, a websecurity.RouteAction, e websecurity.RouteEffect) error {
	if !a.Valid() {
		return websecurity.ErrRouteActionInvalid
	}
	if !e.Valid() {
		return websecurity.ErrRouteEffectInvalid
	}
	if !g.h.accepts(s) || !g.h.actions[a] {
		return host.ErrActionDenied
	}
	return nil
}
func singleHeader(r *http.Request, name string) string {
	values := r.Header.Values(name)
	if len(values) != 1 || strings.Contains(values[0], ",") {
		return ""
	}
	return values[0]
}
