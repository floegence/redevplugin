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

func TestConfirmationTokenBindsRequestHashAndConsumesOnce(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	audience := testSurfaceAudience("bridge_1")
	audience.Method = "danger.run"
	audience.RequestHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	result, err := service.MintConfirmationToken(MintConfirmationTokenRequest{
		PluginInstanceID:     audience.PluginInstanceID,
		ActiveFingerprint:    audience.ActiveFingerprint,
		SurfaceInstanceID:    audience.SurfaceInstanceID,
		OwnerSessionHash:     audience.OwnerSessionHash,
		OwnerUserHash:        audience.OwnerUserHash,
		SessionChannelIDHash: audience.SessionChannelIDHash,
		BridgeChannelID:      audience.BridgeChannelID,
		Method:               audience.Method,
		RequestHash:          audience.RequestHash,
		Revision:             testRevision(4),
		Now:                  now,
	})
	if err != nil {
		t.Fatalf("MintConfirmationToken() error = %v", err)
	}
	if result.ConfirmationToken == "" || result.RequestHash != audience.RequestHash {
		t.Fatalf("confirmation result mismatch: %#v", result)
	}

	wrongAudience := audience
	wrongAudience.RequestHash = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	if _, err := service.ValidateConfirmationToken(ValidateConfirmationTokenRequest{
		ConfirmationToken: result.ConfirmationToken,
		Audience:          wrongAudience,
		Revision:          testRevision(4),
		Now:               now.Add(time.Second),
	}); !errors.Is(err, ErrTokenAudience) {
		t.Fatalf("ValidateConfirmationToken() wrong hash error = %v, want %v", err, ErrTokenAudience)
	}

	if _, err := service.ValidateConfirmationToken(ValidateConfirmationTokenRequest{
		ConfirmationToken: result.ConfirmationToken,
		Audience:          audience,
		Revision:          testRevision(4),
		Now:               now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("ValidateConfirmationToken() error = %v", err)
	}
	if _, err := service.ValidateConfirmationToken(ValidateConfirmationTokenRequest{
		ConfirmationToken: result.ConfirmationToken,
		Audience:          audience,
		Revision:          testRevision(4),
		Now:               now.Add(3 * time.Second),
	}); !errors.Is(err, ErrTokenReplay) {
		t.Fatalf("ValidateConfirmationToken() replay error = %v, want %v", err, ErrTokenReplay)
	}
}

func TestConfirmationTokenRequiresBoundMethodAndRequestHash(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	audience := testSurfaceAudience("bridge_1")
	audience.Method = "danger.run"
	audience.RequestHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	req := MintConfirmationTokenRequest{
		PluginInstanceID:     audience.PluginInstanceID,
		ActiveFingerprint:    audience.ActiveFingerprint,
		SurfaceInstanceID:    audience.SurfaceInstanceID,
		OwnerSessionHash:     audience.OwnerSessionHash,
		OwnerUserHash:        audience.OwnerUserHash,
		SessionChannelIDHash: audience.SessionChannelIDHash,
		BridgeChannelID:      audience.BridgeChannelID,
		Method:               audience.Method,
		RequestHash:          audience.RequestHash,
		Revision:             testRevision(4),
		Now:                  now,
	}
	missingMethod := req
	missingMethod.Method = ""
	if _, err := service.MintConfirmationToken(missingMethod); !errors.Is(err, ErrMissingTokenAudience) {
		t.Fatalf("MintConfirmationToken() missing method error = %v, want %v", err, ErrMissingTokenAudience)
	}
	badHash := req
	badHash.RequestHash = "sha256:not-a-real-hash"
	if _, err := service.MintConfirmationToken(badHash); !errors.Is(err, ErrTokenAudience) {
		t.Fatalf("MintConfirmationToken() invalid hash error = %v, want %v", err, ErrTokenAudience)
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
