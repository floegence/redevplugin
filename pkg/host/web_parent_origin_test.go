package host

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

type loopbackParentOrigins struct{ parent string }

func (o loopbackParentOrigins) AllocateSurfaceOrigin(_ context.Context, req SurfaceOriginRequest) (SurfaceOrigin, error) {
	return SurfaceOrigin{Origin: "http://" + req.OriginKey + ".localhost:4100", ParentOrigin: o.parent}, nil
}

func TestWebSurfaceCanonicalLoopbackParentOrigins(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/contracts/web-surface-parent-origins.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Origin   string
			Accepted bool
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	h, _, _ := newTestHost(t, true, true)
	installed := installAndEnablePlugin(t, h, buildFixturePackage(t))
	for index, item := range fixture.Cases {
		t.Run(item.Origin, func(t *testing.T) {
			h.webOrigins = loopbackParentOrigins{parent: item.Origin}
			now := stableRecentTestNow()
			bootstrap, err := h.OpenSurface(hostTestContext(), OpenSurfaceRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceID: "lifecycle.view", SurfaceInstanceID: fmt.Sprintf("surface_parent_%d", index), ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID), Now: now})
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := h.PrepareSurface(hostTestContext(), exchangeAssetTicketRequestForBootstrap(bootstrap, now))
			if (err == nil) != item.Accepted {
				t.Fatalf("parent accepted=%t, want %t: %v", err == nil, item.Accepted, err)
			}
			if item.Accepted && prepared.Document.ParentOrigin != item.Origin {
				t.Fatal("parent identity changed")
			}
		})
	}
}

func TestWebSurfaceChildStillRejectsLoopbackIPOrigins(t *testing.T) {
	for _, origin := range []string{"http://127.0.0.1:4100", "http://[::1]:4100"} {
		if _, err := validateWebOrigin(origin); err == nil {
			t.Fatalf("accepted child %s", origin)
		}
	}
}
