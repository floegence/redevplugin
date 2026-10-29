package httpadapter

import (
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
)

//go:embed web_surface_bootstrap.js
var webSurfaceBootstrapScript string

const webSurfaceCookie = "__Host-rdp-surface"

// WebSurfaceOrigin resolves a trusted routing origin, never a forwarded header
// supplied by a plugin. Reverse proxies provide their verified TLS binding.
type WebSurfaceOrigin func(*http.Request) (string, error)

// NewWebSurfaceHandler serves only package resources and the platform bootstrap.
// Mount it on dedicated child origins, separately from management routes.
func NewWebSurfaceHandler(platform *host.Host, origin WebSurfaceOrigin) (http.Handler, error) {
	if platform == nil || origin == nil {
		return nil, errors.New("host and trusted Web origin resolver are required")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveWebSurface(platform, origin, w, r) }), nil
}

func serveWebSurface(platform *host.Host, resolve WebSurfaceOrigin, w http.ResponseWriter, r *http.Request) {
	setWebSurfaceHeaders(w)
	origin, err := resolve(r)
	if err != nil {
		http.Error(w, "Web application origin denied", http.StatusForbidden)
		return
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host != r.Host || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil || (parsed.Scheme != "https" && (parsed.Scheme != "http" || !strings.HasSuffix(parsed.Hostname(), ".localhost"))) {
		http.Error(w, "Web application origin denied", http.StatusForbidden)
		return
	}
	if r.URL.RawPath != "" || strings.ContainsAny(r.URL.Path, "\\%\x00") || r.Header.Get("Sec-Fetch-Dest") == "serviceworker" || r.Header.Get("Service-Worker") != "" {
		http.Error(w, "Unsupported application request", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	route := strings.TrimPrefix(r.URL.Path, host.WebSurfacePlatformPath)
	internal := strings.HasPrefix(r.URL.Path, host.WebSurfacePlatformPath)
	if internal && route == "bootstrap" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<!doctype html><html><head><meta charset="utf-8"><title>Application</title></head><body><script src="/_redevplugin_web/bootstrap.js"></script></body></html>`)
		return
	}
	if internal && route == "bootstrap.js" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = io.WriteString(w, webSurfaceBootstrapScript)
		return
	}
	if internal && route == "enter" && r.Method == http.MethodPost {
		if r.Header.Get("Origin") != origin || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var input struct {
			Token string `json:"token"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		session, err := platform.EnterWebSurface(r.Context(), host.WebSurfaceRequest{Origin: origin, Token: input.Token})
		if err != nil {
			http.Error(w, "Application entry expired", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: webSurfaceCookie, Value: session.ResourceToken, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode, Partitioned: true})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			ParentOrigin string `json:"parent_origin"`
			EntryPath    string `json:"entry_path"`
		}{session.ParentOrigin, session.EntryPath})
		return
	}
	cookie, err := r.Cookie(webSurfaceCookie)
	if err != nil {
		http.Error(w, "Application session required", http.StatusForbidden)
		return
	}
	request := host.WebSurfaceRequest{Origin: origin, Token: cookie.Value}
	session, err := platform.ValidateWebSurface(r.Context(), request)
	if err != nil {
		http.Error(w, "Application session expired", http.StatusGone)
		return
	}
	w.Header().Set("Content-Security-Policy", webSurfaceCSP+"; frame-ancestors "+session.ParentOrigin)
	if internal {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		switch route {
		case "resume":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"parent_origin": session.ParentOrigin, "entry_path": session.EntryPath})
			return
		case "probe":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "redevplugin-web-boundary")
			return
		case "probe-redirect":
			w.Header().Set("Location", host.WebSurfacePlatformPath+"probe")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		case "document":
			target := r.URL.Query().Get("path")
			if target == "" {
				target = session.EntryPath
			}
			decoded, decodeErr := url.PathUnescape(target)
			if decodeErr != nil || (decoded != target && (&url.URL{Path: decoded}).EscapedPath() != target) {
				http.Error(w, "Application document path denied", http.StatusForbidden)
				return
			}
			serveWebAsset(platform, w, r, request, decoded, true)
			return
		default:
			http.NotFound(w, r)
			return
		}
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	destination := r.Header.Get("Sec-Fetch-Dest")
	if destination == "iframe" || destination == "document" {
		// Every document navigation re-enters the trusted loader, including SPA routes.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<!doctype html><html><head><meta charset="utf-8"><title>Application</title></head><body><script src="/_redevplugin_web/bootstrap.js"></script></body></html>`)
		return
	}
	serveWebAsset(platform, w, r, request, r.URL.Path, false)
}

func serveWebAsset(platform *host.Host, w http.ResponseWriter, r *http.Request, session host.WebSurfaceRequest, assetPath string, navigation bool) {
	asset, err := platform.ReadWebSurfaceAsset(r.Context(), host.ReadWebSurfaceAssetRequest{WebSurfaceRequest: session, Path: assetPath, Navigation: navigation})
	if err != nil {
		if errors.Is(err, pluginpkg.ErrPackageAssetNotFound) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Application resource denied", http.StatusForbidden)
		}
		return
	}
	if strings.Contains(asset.Entry.ContentType, "text/html") && !navigation {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", asset.Entry.ContentType)
	if r.Method != http.MethodHead {
		_, _ = w.Write(asset.Content)
	}
}

const webSurfaceCSP = "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; media-src 'self' blob:; worker-src 'self' blob:; connect-src 'self'; frame-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'; manifest-src 'none'"

func setWebSurfaceHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", webSurfaceCSP)
	w.Header().Set("Origin-Agent-Cluster", "?1")
	w.Header().Set("Connection-Allowlist", "(response-origin)")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), hid=(), bluetooth=(), publickey-credentials-get=()")
}
