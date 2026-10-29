package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/httpadapter"
)

// localWebOrigins binds the platform loader to a random loopback listener.
// Child hosts only expose the platform asset handler, never management routes.
type localWebOrigins struct{ port string }

func (o localWebOrigins) parentOrigin() string { return "http://localhost:" + o.port }
func (o localWebOrigins) AllocateSurfaceOrigin(_ context.Context, request host.SurfaceOriginRequest) (host.SurfaceOrigin, error) {
	return host.SurfaceOrigin{Origin: "http://" + request.OriginKey + ".localhost:" + o.port, ParentOrigin: o.parentOrigin()}, nil
}
func (o localWebOrigins) handler(platform *host.Host, parent http.Handler) (http.Handler, error) {
	child, err := httpadapter.NewWebSurfaceHandler(platform, func(r *http.Request) (string, error) {
		name, port, err := net.SplitHostPort(r.Host)
		if err != nil || port != o.port || !strings.HasSuffix(name, ".localhost") {
			return "", fmt.Errorf("invalid local application origin")
		}
		return "http://" + r.Host, nil
	})
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "localhost:"+o.port {
			parent.ServeHTTP(w, r)
			return
		}
		child.ServeHTTP(w, r)
	}), nil
}
