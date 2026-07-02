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

func TestValidateAssetSessionReturnsSurfaceSession(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	bootstrap, err := service.OpenSurface(testOpenSurfaceRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.ExchangeAssetTicket(ExchangeAssetTicketRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetTicket:       bootstrap.AssetTicket,
		Now:               now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	validation, err := service.ValidateAssetSession(ValidateAssetSessionRequest{
		AssetSession: result.AssetSession,
		Now:          now.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatalf("ValidateAssetSession() error = %v", err)
	}
	if validation.Session.PluginInstanceID != bootstrap.PluginInstanceID ||
		validation.Session.SurfaceInstanceID != bootstrap.SurfaceInstanceID ||
		validation.Session.BridgeNonce != bootstrap.BridgeNonce {
		t.Fatalf("asset session validation mismatch: %#v", validation)
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

func TestSurfaceRevokePluginDropsSessionsAndTokens(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	bootstrap, gateway := mintTestGatewayToken(t, service, now)
	audience := testSurfaceAudience("bridge_1")

	if revoked := service.RevokePlugin(audience.PluginInstanceID, 0, now.Add(4*time.Second)); revoked == 0 {
		t.Fatal("RevokePlugin() revoked no tokens")
	}
	if _, err := service.ValidateGatewayToken(gateway.GatewayToken, audience, testRevision(4), now.Add(5*time.Second)); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("ValidateGatewayToken() after plugin revoke error = %v, want %v", err, ErrTokenRevoked)
	}
	if _, err := service.ExchangeAssetTicket(ExchangeAssetTicketRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetTicket:       bootstrap.AssetTicket,
		Now:               now.Add(6 * time.Second),
	}); !errors.Is(err, ErrSurfaceSessionNotFound) {
		t.Fatalf("ExchangeAssetTicket() after plugin revoke error = %v, want %v", err, ErrSurfaceSessionNotFound)
	}
}

func TestConfirmationTokenBindsRequestHashAndConsumesOnce(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	audience := testSurfaceAudience("bridge_1")
	audience.ConfirmationID = "confirmation_1"
	audience.Method = "danger.run"
	audience.RequestHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	result, err := service.MintConfirmationToken(MintConfirmationTokenRequest{
		PluginInstanceID:     audience.PluginInstanceID,
		ActiveFingerprint:    audience.ActiveFingerprint,
		SurfaceInstanceID:    audience.SurfaceInstanceID,
		ConfirmationID:       audience.ConfirmationID,
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
	audience.ConfirmationID = "confirmation_1"
	audience.Method = "danger.run"
	audience.RequestHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	req := MintConfirmationTokenRequest{
		PluginInstanceID:     audience.PluginInstanceID,
		ActiveFingerprint:    audience.ActiveFingerprint,
		SurfaceInstanceID:    audience.SurfaceInstanceID,
		ConfirmationID:       audience.ConfirmationID,
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
	missingConfirmationID := req
	missingConfirmationID.ConfirmationID = ""
	if _, err := service.MintConfirmationToken(missingConfirmationID); !errors.Is(err, ErrMissingTokenAudience) {
		t.Fatalf("MintConfirmationToken() missing confirmation id error = %v, want %v", err, ErrMissingTokenAudience)
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

func TestRuntimeExecutionLeaseBindsRuntimeGenerationAndMethod(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	revision := testRevision(8)
	result, err := service.MintRuntimeExecutionLease(MintRuntimeExecutionLeaseRequest{
		PluginInstanceID:    "plugini_test",
		ActiveFingerprint:   "sha256:package",
		RuntimeInstanceID:   "runtime_1",
		RuntimeGenerationID: "runtime_gen_1",
		RuntimeShardID:      "runtime_shard_a",
		Method:              "worker.echo",
		Revision:            revision,
		Now:                 now,
	})
	if err != nil {
		t.Fatalf("MintRuntimeExecutionLease() error = %v", err)
	}
	if result.LeaseToken == "" || result.LeaseID == "" || result.LeaseNonce == "" || result.RuntimeGenerationID != "runtime_gen_1" {
		t.Fatalf("runtime lease result mismatch: %#v", result)
	}

	managerRecordAudience := Audience{
		PluginInstanceID:    "plugini_test",
		ActiveFingerprint:   "sha256:package",
		RuntimeInstanceID:   "runtime_1",
		RuntimeGenerationID: "runtime_gen_1",
		RuntimeShardID:      "runtime_shard_a",
		Method:              "worker.echo",
	}
	record, err := service.tokens.Validate(ValidateRequest{
		Kind:     TokenKindRuntimeExecutionLease,
		Token:    result.LeaseToken,
		Audience: managerRecordAudience,
		Revision: revision,
		Now:      now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("Validate(runtime lease) error = %v", err)
	}
	if record.Use != TokenUseReusable {
		t.Fatalf("runtime lease use = %s, want %s", record.Use, TokenUseReusable)
	}
	if record.Nonce != result.LeaseNonce {
		t.Fatalf("runtime lease nonce = %q, want minted nonce %q", result.LeaseNonce, record.Nonce)
	}

	wrongAudience := managerRecordAudience
	wrongAudience.Method = "worker.other"
	if _, err := service.tokens.Validate(ValidateRequest{
		Kind:     TokenKindRuntimeExecutionLease,
		Token:    result.LeaseToken,
		Audience: wrongAudience,
		Revision: revision,
		Now:      now.Add(2 * time.Second),
	}); !errors.Is(err, ErrTokenAudience) {
		t.Fatalf("Validate(runtime lease wrong method) error = %v, want %v", err, ErrTokenAudience)
	}
}

func TestRuntimeExecutionLeaseRequiresGenerationAndMethod(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	req := MintRuntimeExecutionLeaseRequest{
		PluginInstanceID:  "plugini_test",
		ActiveFingerprint: "sha256:package",
		Method:            "worker.echo",
		Revision:          testRevision(8),
		Now:               testNow(),
	}
	if _, err := service.MintRuntimeExecutionLease(req); !errors.Is(err, ErrMissingTokenAudience) {
		t.Fatalf("MintRuntimeExecutionLease() missing generation error = %v, want %v", err, ErrMissingTokenAudience)
	}
	req.RuntimeGenerationID = "runtime_gen_1"
	req.Method = ""
	if _, err := service.MintRuntimeExecutionLease(req); !errors.Is(err, ErrMissingTokenAudience) {
		t.Fatalf("MintRuntimeExecutionLease() missing method error = %v, want %v", err, ErrMissingTokenAudience)
	}
}

func TestRuntimeExecutionLeaseTTLIsClamped(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	result, err := service.MintRuntimeExecutionLease(MintRuntimeExecutionLeaseRequest{
		PluginInstanceID:    "plugini_test",
		ActiveFingerprint:   "sha256:package",
		RuntimeGenerationID: "runtime_gen_1",
		Method:              "worker.echo",
		Revision:            testRevision(8),
		Now:                 now,
		ExpiresAt:           now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("MintRuntimeExecutionLease() error = %v", err)
	}
	if got := result.ExpiresAt.Sub(now); got != MaxRuntimeLeaseTTL {
		t.Fatalf("runtime lease ttl = %s, want %s", got, MaxRuntimeLeaseTTL)
	}
}

func TestHandleGrantBindsRuntimeGenerationHandleAndMethod(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	revision := testRevision(9)
	limits := Limits{MaxBytesPerSecond: 4096, MaxTotalBytes: 32768}
	result, err := service.MintHandleGrant(MintHandleGrantRequest{
		PluginInstanceID:    "plugini_test",
		ActiveFingerprint:   "sha256:package",
		RuntimeInstanceID:   "runtime_1",
		RuntimeGenerationID: "runtime_gen_1",
		RuntimeShardID:      "runtime_shard_a",
		HandleID:            "handle_network_1",
		Method:              "network.open",
		Revision:            revision,
		Limits:              limits,
		Now:                 now,
	})
	if err != nil {
		t.Fatalf("MintHandleGrant() error = %v", err)
	}
	if result.HandleGrantToken == "" || result.HandleGrantID == "" ||
		result.RuntimeGenerationID != "runtime_gen_1" || result.HandleID != "handle_network_1" {
		t.Fatalf("handle grant result mismatch: %#v", result)
	}
	if result.Limits != limits {
		t.Fatalf("handle grant limits = %#v, want %#v", result.Limits, limits)
	}

	audience := Audience{
		PluginInstanceID:    "plugini_test",
		ActiveFingerprint:   "sha256:package",
		RuntimeInstanceID:   "runtime_1",
		RuntimeGenerationID: "runtime_gen_1",
		RuntimeShardID:      "runtime_shard_a",
		HandleID:            "handle_network_1",
		Method:              "network.open",
	}
	record, err := service.ValidateHandleGrant(ValidateHandleGrantRequest{
		HandleGrantToken: result.HandleGrantToken,
		Audience:         audience,
		Revision:         revision,
		Now:              now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("ValidateHandleGrant() error = %v", err)
	}
	if record.Use != TokenUseReusable || record.Limits != limits {
		t.Fatalf("handle grant record mismatch: %#v", record)
	}

	wrongHandle := audience
	wrongHandle.HandleID = "handle_network_2"
	if _, err := service.ValidateHandleGrant(ValidateHandleGrantRequest{
		HandleGrantToken: result.HandleGrantToken,
		Audience:         wrongHandle,
		Revision:         revision,
		Now:              now.Add(2 * time.Second),
	}); !errors.Is(err, ErrTokenAudience) {
		t.Fatalf("ValidateHandleGrant() wrong handle error = %v, want %v", err, ErrTokenAudience)
	}
}

func TestHandleGrantRequiresRuntimeGenerationHandleAndMethod(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	req := MintHandleGrantRequest{
		PluginInstanceID:    "plugini_test",
		ActiveFingerprint:   "sha256:package",
		RuntimeGenerationID: "runtime_gen_1",
		HandleID:            "handle_network_1",
		Method:              "network.open",
		Revision:            testRevision(9),
		Now:                 testNow(),
	}
	missingGeneration := req
	missingGeneration.RuntimeGenerationID = ""
	if _, err := service.MintHandleGrant(missingGeneration); !errors.Is(err, ErrMissingTokenAudience) {
		t.Fatalf("MintHandleGrant() missing generation error = %v, want %v", err, ErrMissingTokenAudience)
	}
	missingHandle := req
	missingHandle.HandleID = ""
	if _, err := service.MintHandleGrant(missingHandle); !errors.Is(err, ErrMissingTokenAudience) {
		t.Fatalf("MintHandleGrant() missing handle error = %v, want %v", err, ErrMissingTokenAudience)
	}
	missingMethod := req
	missingMethod.Method = ""
	if _, err := service.MintHandleGrant(missingMethod); !errors.Is(err, ErrMissingTokenAudience) {
		t.Fatalf("MintHandleGrant() missing method error = %v, want %v", err, ErrMissingTokenAudience)
	}

	result, err := service.MintHandleGrant(req)
	if err != nil {
		t.Fatalf("MintHandleGrant() error = %v", err)
	}
	audience := Audience{
		PluginInstanceID:    req.PluginInstanceID,
		ActiveFingerprint:   req.ActiveFingerprint,
		RuntimeGenerationID: req.RuntimeGenerationID,
		HandleID:            req.HandleID,
	}
	if _, err := service.ValidateHandleGrant(ValidateHandleGrantRequest{
		HandleGrantToken: result.HandleGrantToken,
		Audience:         audience,
		Revision:         req.Revision,
		Now:              req.Now.Add(time.Second),
	}); !errors.Is(err, ErrMissingTokenAudience) {
		t.Fatalf("ValidateHandleGrant() missing method error = %v, want %v", err, ErrMissingTokenAudience)
	}
}

func TestHandleGrantRevisionMismatchAndTTLClamp(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	result, err := service.MintHandleGrant(MintHandleGrantRequest{
		PluginInstanceID:    "plugini_test",
		ActiveFingerprint:   "sha256:package",
		RuntimeGenerationID: "runtime_gen_1",
		HandleID:            "handle_storage_1",
		Method:              "storage.read",
		Revision:            testRevision(9),
		Now:                 now,
		ExpiresAt:           now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("MintHandleGrant() error = %v", err)
	}
	if got := result.ExpiresAt.Sub(now); got != MaxHandleGrantTTL {
		t.Fatalf("handle grant ttl = %s, want %s", got, MaxHandleGrantTTL)
	}

	audience := Audience{
		PluginInstanceID:    "plugini_test",
		ActiveFingerprint:   "sha256:package",
		RuntimeGenerationID: "runtime_gen_1",
		HandleID:            "handle_storage_1",
		Method:              "storage.read",
	}
	if _, err := service.ValidateHandleGrant(ValidateHandleGrantRequest{
		HandleGrantToken: result.HandleGrantToken,
		Audience:         audience,
		Revision:         testRevision(10),
		Now:              now.Add(time.Second),
	}); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("ValidateHandleGrant() stale revision error = %v, want %v", err, ErrTokenRevoked)
	}
}

func TestStreamTicketBindsStreamDirectionAndConsumesOnce(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	audience := testSurfaceAudience("bridge_1")
	audience.StreamID = "stream_logs_1"
	audience.StreamDirection = "read"
	audience.Method = "logs.tail"
	result, err := service.MintStreamTicket(MintStreamTicketRequest{
		PluginInstanceID:     audience.PluginInstanceID,
		ActiveFingerprint:    audience.ActiveFingerprint,
		SurfaceInstanceID:    audience.SurfaceInstanceID,
		OwnerSessionHash:     audience.OwnerSessionHash,
		OwnerUserHash:        audience.OwnerUserHash,
		SessionChannelIDHash: audience.SessionChannelIDHash,
		BridgeChannelID:      audience.BridgeChannelID,
		StreamID:             audience.StreamID,
		StreamDirection:      audience.StreamDirection,
		Method:               audience.Method,
		Revision:             testRevision(11),
		Now:                  now,
	})
	if err != nil {
		t.Fatalf("MintStreamTicket() error = %v", err)
	}
	if result.StreamTicket == "" || result.StreamID != audience.StreamID || result.Direction != "read" {
		t.Fatalf("stream ticket result mismatch: %#v", result)
	}

	wrongAudience := audience
	wrongAudience.StreamDirection = "write"
	if _, err := service.ValidateStreamTicket(ValidateStreamTicketRequest{
		StreamTicket: result.StreamTicket,
		Audience:     wrongAudience,
		Revision:     testRevision(11),
		Now:          now.Add(time.Second),
	}); !errors.Is(err, ErrTokenAudience) {
		t.Fatalf("ValidateStreamTicket() wrong direction error = %v, want %v", err, ErrTokenAudience)
	}
	if _, err := service.ValidateStreamTicket(ValidateStreamTicketRequest{
		StreamTicket: result.StreamTicket,
		Audience:     audience,
		Revision:     testRevision(11),
		Now:          now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("ValidateStreamTicket() error = %v", err)
	}
	if _, err := service.ValidateStreamTicket(ValidateStreamTicketRequest{
		StreamTicket: result.StreamTicket,
		Audience:     audience,
		Revision:     testRevision(11),
		Now:          now.Add(3 * time.Second),
	}); !errors.Is(err, ErrTokenReplay) {
		t.Fatalf("ValidateStreamTicket() replay error = %v, want %v", err, ErrTokenReplay)
	}
}

func TestStreamTicketRequiresStreamDirectionAndMethod(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	audience := testSurfaceAudience("bridge_1")
	req := MintStreamTicketRequest{
		PluginInstanceID:     audience.PluginInstanceID,
		ActiveFingerprint:    audience.ActiveFingerprint,
		SurfaceInstanceID:    audience.SurfaceInstanceID,
		OwnerSessionHash:     audience.OwnerSessionHash,
		OwnerUserHash:        audience.OwnerUserHash,
		SessionChannelIDHash: audience.SessionChannelIDHash,
		BridgeChannelID:      audience.BridgeChannelID,
		StreamID:             "stream_logs_1",
		StreamDirection:      "read",
		Method:               "logs.tail",
		Revision:             testRevision(11),
		Now:                  testNow(),
	}
	missingDirection := req
	missingDirection.StreamDirection = ""
	if _, err := service.MintStreamTicket(missingDirection); !errors.Is(err, ErrMissingTokenAudience) {
		t.Fatalf("MintStreamTicket() missing direction error = %v, want %v", err, ErrMissingTokenAudience)
	}
	badDirection := req
	badDirection.StreamDirection = "sideways"
	if _, err := service.MintStreamTicket(badDirection); !errors.Is(err, ErrMissingTokenAudience) {
		t.Fatalf("MintStreamTicket() bad direction error = %v, want %v", err, ErrMissingTokenAudience)
	}
	missingMethod := req
	missingMethod.Method = ""
	if _, err := service.MintStreamTicket(missingMethod); !errors.Is(err, ErrMissingTokenAudience) {
		t.Fatalf("MintStreamTicket() missing method error = %v, want %v", err, ErrMissingTokenAudience)
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
