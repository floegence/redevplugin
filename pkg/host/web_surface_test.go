package host

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
)

func TestWebSurfaceEntryLeaseRevocationAndIndependentContainers(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed := installAndEnablePlugin(t, h, buildFixturePackage(t))
	now := stableRecentTestNow()
	type opened struct {
		bootstrap bridge.SurfaceBootstrap
		document  WebSurfaceDocument
		request   WebSurfaceRequest
		gateway   bridge.GatewayTokenResult
	}
	open := func(id string) opened {
		t.Helper()
		bootstrap, err := h.OpenSurface(hostTestContext(), OpenSurfaceRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceID: "lifecycle.view", SurfaceInstanceID: id, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID), Now: now})
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := h.PrepareSurface(hostTestContext(), exchangeAssetTicketRequestForBootstrap(bootstrap, now))
		if err != nil {
			t.Fatal(err)
		}
		entry, _ := url.Parse(prepared.Document.BootstrapURL)
		req := WebSurfaceRequest{Origin: prepared.Document.Origin, Token: entry.Fragment, Now: now}
		session, err := h.EnterWebSurface(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.EnterWebSurface(context.Background(), req); err == nil {
			t.Fatal("entry credential replay accepted")
		}
		req.Token = session.ResourceToken
		if _, err := h.ReadWebSurfaceAsset(context.Background(), ReadWebSurfaceAssetRequest{WebSurfaceRequest: req, Path: "/assets/status.png"}); !errors.Is(err, bridge.ErrAssetSessionRequired) {
			t.Fatalf("package bytes before gateway admission: %v", err)
		}
		handshake := bridge.Handshake{PluginID: bootstrap.PluginID, SurfaceID: bootstrap.SurfaceID, SurfaceInstanceID: bootstrap.SurfaceInstanceID, ActiveFingerprint: bootstrap.ActiveFingerprint, BridgeNonce: bootstrap.BridgeNonce, AssetSessionNonce: bootstrap.AssetSessionNonce, ManagementRevision: bootstrap.ManagementRevision, RevokeEpoch: bootstrap.RevokeEpoch}
		channel := "bridge_" + id
		gateway, err := h.MintBridgeToken(hostTestContext(), MintBridgeTokenRequest{Handshake: handshake, BridgeChannelID: channel, HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, channel), Now: now})
		if err != nil {
			t.Fatal(err)
		}
		return opened{bootstrap, prepared.Document, req, gateway}
	}
	first, second := open("surface_web_first"), open("surface_web_second")
	if first.document.Origin == second.document.Origin {
		t.Fatal("containers share origin")
	}
	asset, err := h.ReadWebSurfaceAsset(context.Background(), ReadWebSurfaceAssetRequest{WebSurfaceRequest: first.request, Path: "/assets/status.png"})
	if err != nil || !bytes.Equal(asset.Content, validPNGForTest()) {
		t.Fatalf("native resource read: %v", err)
	}
	wrong := first.request
	wrong.Origin = second.document.Origin
	if _, err := h.ValidateWebSurface(context.Background(), wrong); err == nil {
		t.Fatal("sibling credential accepted")
	}
	for _, path := range []string{"/../manifest.json", "/%2e%2e/manifest.json", "/assets/../index.html", "/.hidden", "/_redevplugin_web/enter", "//assets/status.png"} {
		if _, err := h.ReadWebSurfaceAsset(context.Background(), ReadWebSurfaceAssetRequest{WebSurfaceRequest: first.request, Path: path}); !errors.Is(err, pluginpkg.ErrInvalidAssetPath) {
			t.Errorf("path %q: %v", path, err)
		}
	}
	b := first.bootstrap
	handshake := bridge.Handshake{PluginID: b.PluginID, SurfaceID: b.SurfaceID, SurfaceInstanceID: b.SurfaceInstanceID, ActiveFingerprint: b.ActiveFingerprint, BridgeNonce: b.BridgeNonce, AssetSessionNonce: b.AssetSessionNonce, ManagementRevision: b.ManagementRevision, RevokeEpoch: b.RevokeEpoch}
	channel := "bridge_" + b.SurfaceInstanceID
	renewAt := first.gateway.ExpiresAt.Add(-time.Second)
	_, err = h.MintBridgeToken(hostTestContext(), MintBridgeTokenRequest{Handshake: handshake, BridgeChannelID: channel, HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, channel), PreviousGatewayToken: first.gateway.GatewayToken, Now: renewAt})
	if err != nil {
		t.Fatal(err)
	}
	first.request.Now = first.gateway.ExpiresAt.Add(time.Second)
	if _, err := h.ReadWebSurfaceAsset(context.Background(), ReadWebSurfaceAssetRequest{WebSurfaceRequest: first.request, Path: "/assets/status.png"}); err != nil {
		t.Fatalf("resource credential did not follow renewed lease: %v", err)
	}
	if err := h.DisposeSurface(hostTestContext(), DisposeSurfaceRequest{SurfaceInstanceID: b.SurfaceInstanceID, BridgeNonce: b.BridgeNonce, Now: first.request.Now}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ValidateWebSurface(context.Background(), first.request); err == nil {
		t.Fatal("closed origin accepted")
	}
	if _, err := h.ValidateWebSurface(context.Background(), second.request); err != nil {
		t.Fatalf("closing first invalidated sibling: %v", err)
	}
	h.webSurfaces.mu.Lock()
	count := len(h.webSurfaces.byOrigin)
	h.webSurfaces.mu.Unlock()
	if count != 1 {
		t.Fatalf("live bindings=%d", count)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ValidateWebSurface(context.Background(), second.request); !errors.Is(err, ErrHostClosed) {
		t.Fatalf("closed Host: %v", err)
	}
}

func TestWebSurfaceRejectsUnsafeOrigins(t *testing.T) {
	for _, origin := range []string{"http://example.com", "https://example.com/", "https://user:password@example.com", "https://example.com?x=1", "https://example.com#x", "file:///app", "https://example.com\\evil"} {
		if _, err := validateWebOrigin(origin); err == nil {
			t.Errorf("accepted %s", origin)
		}
	}
	for _, origin := range []string{"https://app.example", "http://app.localhost:4100"} {
		if _, err := validateWebOrigin(origin); err != nil {
			t.Errorf("rejected %s: %v", origin, err)
		}
	}
	if !strings.HasPrefix(WebSurfacePlatformPath, "/") {
		t.Fatal("platform path must be absolute")
	}
}

func openTestWebSurface(t *testing.T, h *Host, pluginID, surfaceID string, contexts ...context.Context) (WebSurfaceRequest, bridge.SurfaceBootstrap) {
	t.Helper()
	ctx := hostTestContext()
	if len(contexts) > 0 {
		ctx = contexts[0]
	}
	now := stableRecentTestNow()
	b, err := h.OpenSurface(ctx, OpenSurfaceRequest{PluginInstanceID: pluginID, SurfaceID: "lifecycle.view", SurfaceInstanceID: surfaceID, ExpectedManagementRevision: mustManagementRevision(t, h, pluginID), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := h.PrepareSurface(ctx, exchangeAssetTicketRequestForBootstrap(b, now))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := url.Parse(prepared.Document.BootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	req := WebSurfaceRequest{Origin: prepared.Document.Origin, Token: entry.Fragment, Now: now}
	session, err := h.EnterWebSurface(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.Token = session.ResourceToken
	handshake := bridge.Handshake{PluginID: b.PluginID, SurfaceID: b.SurfaceID, SurfaceInstanceID: b.SurfaceInstanceID, ActiveFingerprint: b.ActiveFingerprint, BridgeNonce: b.BridgeNonce, AssetSessionNonce: b.AssetSessionNonce, ManagementRevision: b.ManagementRevision, RevokeEpoch: b.RevokeEpoch}
	channel := "bridge_" + surfaceID
	_, err = h.MintBridgeToken(ctx, MintBridgeTokenRequest{Handshake: handshake, BridgeChannelID: channel, HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, channel), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return req, b
}

func TestWebSurfaceRechecksRevocationAfterAssetRead(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed := installAndEnablePlugin(t, h, buildFixturePackage(t))
	request, surface := openTestWebSurface(t, h, installed.PluginInstanceID, "surface_read_revoke")
	assets := &performanceCountingAssetStore{AssetStore: h.adapters.Assets}
	h.adapters.Assets = assets
	started, resume := assets.blockNextRead()
	outcome := make(chan error, 1)
	go func() {
		_, err := h.ReadWebSurfaceAsset(context.Background(), ReadWebSurfaceAssetRequest{WebSurfaceRequest: request, Path: "/assets/status.png"})
		outcome <- err
	}()
	<-started
	if err := h.DisposeSurface(hostTestContext(), DisposeSurfaceRequest{SurfaceInstanceID: surface.SurfaceInstanceID, BridgeNonce: surface.BridgeNonce, Now: request.Now}); err != nil {
		close(resume)
		t.Fatal(err)
	}
	close(resume)
	if err := <-outcome; err == nil {
		t.Fatal("resource read completed after its surface was revoked")
	}
}
