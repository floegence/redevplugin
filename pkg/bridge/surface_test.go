package bridge

import (
	"errors"
	"testing"
	"time"
)

func TestSurfaceBootstrapExchangeAndGatewayToken(t *testing.T) {
	manager := NewTokenManager()
	service := NewSurfaceTokenService(manager, SurfaceTokenOptions{})
	now := testNow()

	bootstrap, err := service.OpenSurface(testOpenSurfaceRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	if bootstrap.AssetTicket == "" || bootstrap.BridgeNonce == "" {
		t.Fatalf("bootstrap missing credential fields: %#v", bootstrap)
	}

	assetSession, err := service.ExchangeAssetTicket(ExchangeAssetTicketRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetTicket:       bootstrap.AssetTicket,
		Now:               now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("ExchangeAssetTicket() error = %v", err)
	}
	if assetSession.AssetSession == "" {
		t.Fatalf("assetSession = %#v", assetSession)
	}

	gateway, err := service.MintGatewayToken(MintGatewayTokenRequest{
		Handshake: Handshake{
			PluginID:          bootstrap.PluginID,
			SurfaceID:         bootstrap.SurfaceID,
			SurfaceInstanceID: bootstrap.SurfaceInstanceID,
			ActiveFingerprint: bootstrap.ActiveFingerprint,
			BridgeNonce:       bootstrap.BridgeNonce,
			UIProtocolVersion: "plugin-ui-v1",
		},
		BridgeChannelID: "bridge_1",
		Now:             now.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatalf("MintGatewayToken() error = %v", err)
	}
	if gateway.GatewayToken == "" {
		t.Fatalf("gateway = %#v", gateway)
	}

	audience := testSurfaceAudience("bridge_1")
	record, err := service.ValidateGatewayToken(gateway.GatewayToken, audience, testRevision(4), now.Add(3*time.Second))
	if err != nil {
		t.Fatalf("ValidateGatewayToken() error = %v", err)
	}
	if record.BoundBridgeChannelID != "bridge_1" {
		t.Fatalf("BoundBridgeChannelID = %q", record.BoundBridgeChannelID)
	}
}

func TestSurfaceGatewayRequiresAssetSession(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	bootstrap, err := service.OpenSurface(testOpenSurfaceRequest(now))
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.MintGatewayToken(MintGatewayTokenRequest{
		Handshake:       handshakeFromBootstrap(bootstrap),
		BridgeChannelID: "bridge_1",
		Now:             now.Add(time.Second),
	})
	if !errors.Is(err, ErrAssetSessionRequired) {
		t.Fatalf("MintGatewayToken() error = %v, want %v", err, ErrAssetSessionRequired)
	}
}

func TestSurfaceHandshakeMismatchFailsClosed(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	bootstrap, err := service.OpenSurface(testOpenSurfaceRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ExchangeAssetTicket(ExchangeAssetTicketRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetTicket:       bootstrap.AssetTicket,
		Now:               now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}

	handshake := handshakeFromBootstrap(bootstrap)
	handshake.BridgeNonce = "wrong_nonce"
	_, err = service.MintGatewayToken(MintGatewayTokenRequest{
		Handshake:       handshake,
		BridgeChannelID: "bridge_1",
		Now:             now.Add(2 * time.Second),
	})
	if !errors.Is(err, ErrHandshakeMismatch) {
		t.Fatalf("MintGatewayToken() error = %v, want %v", err, ErrHandshakeMismatch)
	}
}

func TestSurfaceDisposeRevokesGatewayToken(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	bootstrap, gateway := mintTestGatewayToken(t, service, now)
	audience := testSurfaceAudience("bridge_1")

	if !service.DisposeSurface(bootstrap.SurfaceInstanceID, now.Add(4*time.Second)) {
		t.Fatal("DisposeSurface() = false")
	}
	_, err := service.ValidateGatewayToken(gateway.GatewayToken, audience, testRevision(4), now.Add(5*time.Second))
	if !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("ValidateGatewayToken() error = %v, want %v", err, ErrTokenRevoked)
	}
}

func TestAssetTicketTTLIsClamped(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{AssetTicketTTL: 5 * time.Minute})
	now := testNow()
	bootstrap, err := service.OpenSurface(testOpenSurfaceRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	if got := bootstrap.ExpiresAt.Sub(now); got != MaxAssetTicketTTL {
		t.Fatalf("asset ticket ttl = %s, want %s", got, MaxAssetTicketTTL)
	}
}

func mintTestGatewayToken(t *testing.T, service *SurfaceTokenService, now time.Time) (SurfaceBootstrap, GatewayTokenResult) {
	t.Helper()
	bootstrap, err := service.OpenSurface(testOpenSurfaceRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ExchangeAssetTicket(ExchangeAssetTicketRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetTicket:       bootstrap.AssetTicket,
		Now:               now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	gateway, err := service.MintGatewayToken(MintGatewayTokenRequest{
		Handshake:       handshakeFromBootstrap(bootstrap),
		BridgeChannelID: "bridge_1",
		Now:             now.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	return bootstrap, gateway
}

func testOpenSurfaceRequest(now time.Time) OpenSurfaceRequest {
	return OpenSurfaceRequest{
		PluginID:             "com.example.plugin",
		PluginInstanceID:     "plugini_test",
		SurfaceID:            "main.activity",
		SurfaceInstanceID:    "surface_test",
		ActiveFingerprint:    "sha256:package",
		OwnerSessionHash:     "sess_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		Revision:             testRevision(4),
		Now:                  now,
	}
}

func handshakeFromBootstrap(bootstrap SurfaceBootstrap) Handshake {
	return Handshake{
		PluginID:          bootstrap.PluginID,
		SurfaceID:         bootstrap.SurfaceID,
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		ActiveFingerprint: bootstrap.ActiveFingerprint,
		BridgeNonce:       bootstrap.BridgeNonce,
		UIProtocolVersion: "plugin-ui-v1",
	}
}

func testSurfaceAudience(bridgeChannelID string) Audience {
	audience := testAudience()
	audience.BridgeChannelID = bridgeChannelID
	return audience
}
