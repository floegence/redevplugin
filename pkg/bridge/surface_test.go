package bridge

import (
	"errors"
	"strings"
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

	assetSession, err := service.ExchangeAssetTicket(exchangeAssetTicketRequest(bootstrap, now.Add(time.Second)))
	if err != nil {
		t.Fatalf("ExchangeAssetTicket() error = %v", err)
	}
	if assetSession.AssetSession == "" {
		t.Fatalf("assetSession = %#v", assetSession)
	}
	markTestSurfacePrepared(t, service, bootstrap, assetSession, now.Add(time.Second))

	handshake := handshakeFromBootstrap(bootstrap)
	gateway, err := service.MintGatewayToken(MintGatewayTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           "bridge_1",
		HandshakeTranscriptSHA256: HandshakeTranscriptSHA256(handshake, "bridge_1"),
		Now:                       now.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatalf("MintGatewayToken() error = %v", err)
	}
	if gateway.GatewayToken == "" {
		t.Fatalf("gateway = %#v", gateway)
	}

	audience := surfaceAudienceFromBootstrap(bootstrap, "bridge_1")
	record, err := service.ValidateGatewayToken(gateway.GatewayToken, audience, testRevision(4), now.Add(3*time.Second))
	if err != nil {
		t.Fatalf("ValidateGatewayToken() error = %v", err)
	}
	if record.BoundBridgeChannelID != "bridge_1" {
		t.Fatalf("BoundBridgeChannelID = %q", record.BoundBridgeChannelID)
	}
}

func TestSurfaceGatewayRenewalRotatesLeaseCredentialsAndExtendsSession(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{
		AssetSessionTTL: time.Minute,
		GatewayTokenTTL: time.Minute,
	})
	now := testNow()
	bootstrap, err := service.OpenSurface(testOpenSurfaceRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := service.ExchangeAssetTicket(exchangeAssetTicketRequest(bootstrap, now.Add(time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	markTestSurfacePrepared(t, service, bootstrap, prepared, now.Add(time.Second))
	handshake := handshakeFromBootstrap(bootstrap)
	request := MintGatewayTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           "bridge_1",
		HandshakeTranscriptSHA256: HandshakeTranscriptSHA256(handshake, "bridge_1"),
		Now:                       now.Add(2 * time.Second),
	}
	first, err := service.MintGatewayToken(request)
	if err != nil {
		t.Fatal(err)
	}
	if first.AssetSession == "" || first.AssetSessionID == "" || !first.ExpiresAt.Equal(now.Add(62*time.Second)) {
		t.Fatalf("first gateway lease = %#v", first)
	}
	if _, err := service.ValidateAssetSession(ValidateAssetSessionRequest{
		AssetSession:         prepared.AssetSession,
		AssetSessionID:       prepared.AssetSessionID,
		OwnerSessionHash:     bootstrap.OwnerSessionHash,
		OwnerUserHash:        bootstrap.OwnerUserHash,
		SessionChannelIDHash: bootstrap.SessionChannelIDHash,
		Now:                  now.Add(3 * time.Second),
	}); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("prepared asset session after gateway mint error = %v, want %v", err, ErrTokenRevoked)
	}

	request.PreviousGatewayToken = first.GatewayToken
	request.Now = now.Add(50 * time.Second)
	second, err := service.MintGatewayToken(request)
	if err != nil {
		t.Fatal(err)
	}
	if second.GatewayToken == first.GatewayToken || second.AssetSession == first.AssetSession || !second.ExpiresAt.Equal(now.Add(110*time.Second)) {
		t.Fatalf("renewed gateway lease = %#v, first = %#v", second, first)
	}
	audience := surfaceAudienceFromBootstrap(bootstrap, "bridge_1")
	if _, err := service.ValidateGatewayToken(first.GatewayToken, audience, testRevision(4), now.Add(51*time.Second)); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("old gateway token error = %v, want %v", err, ErrTokenRevoked)
	}
	if _, err := service.ValidateAssetSession(ValidateAssetSessionRequest{
		AssetSession:         first.AssetSession,
		AssetSessionID:       first.AssetSessionID,
		OwnerSessionHash:     bootstrap.OwnerSessionHash,
		OwnerUserHash:        bootstrap.OwnerUserHash,
		SessionChannelIDHash: bootstrap.SessionChannelIDHash,
		Now:                  now.Add(51 * time.Second),
	}); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("old asset session error = %v, want %v", err, ErrTokenRevoked)
	}
	if _, err := service.ValidateSurfaceGatewayToken(ValidateSurfaceGatewayTokenRequest{
		GatewayToken:         second.GatewayToken,
		PluginInstanceID:     bootstrap.PluginInstanceID,
		SurfaceInstanceID:    bootstrap.SurfaceInstanceID,
		OwnerSessionHash:     bootstrap.OwnerSessionHash,
		OwnerUserHash:        bootstrap.OwnerUserHash,
		SessionChannelIDHash: bootstrap.SessionChannelIDHash,
		BridgeChannelID:      "bridge_1",
		Revision:             testRevision(4),
		Now:                  now.Add(51 * time.Second),
	}); err != nil {
		t.Fatalf("renewed gateway validation error = %v", err)
	}
}

func TestSurfaceSessionsRejectDuplicatesAndEnforceLimits(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{
		MaxActiveSessions:         2,
		MaxActiveSessionsPerOwner: 1,
	})
	now := testNow()
	first := testOpenSurfaceRequest(now)
	if _, err := service.OpenSurface(first); err != nil {
		t.Fatalf("OpenSurface(first) error = %v", err)
	}

	if _, err := service.OpenSurface(first); !errors.Is(err, ErrSurfaceSessionAlreadyExists) {
		t.Fatalf("OpenSurface(duplicate) error = %v, want %v", err, ErrSurfaceSessionAlreadyExists)
	}
	staleReplacement := first
	staleReplacement.Revision.ManagementRevision++
	if _, err := service.OpenSurface(staleReplacement); err != nil {
		t.Fatalf("OpenSurface(stale replacement) error = %v", err)
	}

	sameOwner := first
	sameOwner.SurfaceInstanceID = "surface_same_owner"
	if _, err := service.OpenSurface(sameOwner); !errors.Is(err, ErrSurfaceSessionLimitReached) {
		t.Fatalf("OpenSurface(same owner) error = %v, want %v", err, ErrSurfaceSessionLimitReached)
	}

	secondOwner := first
	secondOwner.SurfaceInstanceID = "surface_second_owner"
	secondOwner.OwnerSessionHash = "sess_hash_2"
	secondOwner.OwnerUserHash = "user_hash_2"
	secondOwner.SessionChannelIDHash = "channel_hash_2"
	if _, err := service.OpenSurface(secondOwner); err != nil {
		t.Fatalf("OpenSurface(second owner) error = %v", err)
	}

	thirdOwner := first
	thirdOwner.SurfaceInstanceID = "surface_third_owner"
	thirdOwner.OwnerSessionHash = "sess_hash_3"
	thirdOwner.OwnerUserHash = "user_hash_3"
	thirdOwner.SessionChannelIDHash = "channel_hash_3"
	if _, err := service.OpenSurface(thirdOwner); !errors.Is(err, ErrSurfaceSessionLimitReached) {
		t.Fatalf("OpenSurface(global limit) error = %v, want %v", err, ErrSurfaceSessionLimitReached)
	}
}

func TestSurfaceSessionsPruneExpiredEntriesBeforeApplyingLimits(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{
		AssetSessionTTL:           time.Minute,
		MaxActiveSessions:         1,
		MaxActiveSessionsPerOwner: 1,
	})
	now := testNow()
	firstRequest := testOpenSurfaceRequest(now)
	first, err := service.OpenSurface(firstRequest)
	if err != nil {
		t.Fatalf("OpenSurface(first) error = %v", err)
	}

	secondRequest := firstRequest
	secondRequest.SurfaceInstanceID = "surface_after_expiry"
	secondRequest.Now = now.Add(2 * time.Minute)
	if _, err := service.OpenSurface(secondRequest); err != nil {
		t.Fatalf("OpenSurface(after expiry) error = %v", err)
	}

	if _, err := service.ExchangeAssetTicket(exchangeAssetTicketRequest(first, now.Add(2*time.Minute))); !errors.Is(err, ErrSurfaceSessionNotFound) {
		t.Fatalf("ExchangeAssetTicket(expired surface) error = %v, want %v", err, ErrSurfaceSessionNotFound)
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
		Handshake:                 handshakeFromBootstrap(bootstrap),
		BridgeChannelID:           "bridge_1",
		HandshakeTranscriptSHA256: HandshakeTranscriptSHA256(handshakeFromBootstrap(bootstrap), "bridge_1"),
		Now:                       now.Add(time.Second),
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
	result, err := service.ExchangeAssetTicket(exchangeAssetTicketRequest(bootstrap, now.Add(time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	validation, err := service.ValidateAssetSession(ValidateAssetSessionRequest{
		AssetSession:         result.AssetSession,
		AssetSessionID:       result.AssetSessionID,
		OwnerSessionHash:     bootstrap.OwnerSessionHash,
		OwnerUserHash:        bootstrap.OwnerUserHash,
		SessionChannelIDHash: bootstrap.SessionChannelIDHash,
		Now:                  now.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatalf("ValidateAssetSession() error = %v", err)
	}
	if validation.Session.PluginInstanceID != bootstrap.PluginInstanceID ||
		validation.Session.SurfaceInstanceID != bootstrap.SurfaceInstanceID ||
		validation.Session.BridgeNonce != bootstrap.BridgeNonce {
		t.Fatalf("asset session validation mismatch: %#v", validation)
	}
	if _, err := service.ValidateAssetSession(ValidateAssetSessionRequest{
		AssetSession:         result.AssetSession,
		OwnerSessionHash:     bootstrap.OwnerSessionHash,
		OwnerUserHash:        bootstrap.OwnerUserHash,
		SessionChannelIDHash: bootstrap.SessionChannelIDHash,
		Now:                  now.Add(2 * time.Second),
	}); !errors.Is(err, ErrMissingTokenAudience) {
		t.Fatalf("ValidateAssetSession() without asset_session_id error = %v, want %v", err, ErrMissingTokenAudience)
	}
}

func TestSurfaceGatewayRequiresPreparedSurfaceDocument(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	bootstrap, err := service.OpenSurface(testOpenSurfaceRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ExchangeAssetTicket(exchangeAssetTicketRequest(bootstrap, now.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	handshake := handshakeFromBootstrap(bootstrap)
	_, err = service.MintGatewayToken(MintGatewayTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           "bridge_1",
		HandshakeTranscriptSHA256: HandshakeTranscriptSHA256(handshake, "bridge_1"),
		Now:                       now.Add(2 * time.Second),
	})
	if !errors.Is(err, ErrAssetSessionRequired) {
		t.Fatalf("MintGatewayToken() before surface preparation error = %v, want %v", err, ErrAssetSessionRequired)
	}
}

func TestSurfaceHandshakeMismatchFailsClosed(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	bootstrap, err := service.OpenSurface(testOpenSurfaceRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	assetSession, err := service.ExchangeAssetTicket(exchangeAssetTicketRequest(bootstrap, now.Add(time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	markTestSurfacePrepared(t, service, bootstrap, assetSession, now.Add(time.Second))

	handshake := handshakeFromBootstrap(bootstrap)
	handshake.BridgeNonce = "wrong_nonce"
	_, err = service.MintGatewayToken(MintGatewayTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           "bridge_1",
		HandshakeTranscriptSHA256: HandshakeTranscriptSHA256(handshake, "bridge_1"),
		Now:                       now.Add(2 * time.Second),
	})
	if !errors.Is(err, ErrHandshakeMismatch) {
		t.Fatalf("MintGatewayToken() error = %v, want %v", err, ErrHandshakeMismatch)
	}
}

func TestSurfaceGatewayRequiresHandshakeTranscript(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	bootstrap, err := service.OpenSurface(testOpenSurfaceRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	assetSession, err := service.ExchangeAssetTicket(exchangeAssetTicketRequest(bootstrap, now.Add(time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	markTestSurfacePrepared(t, service, bootstrap, assetSession, now.Add(time.Second))

	handshake := handshakeFromBootstrap(bootstrap)
	req := MintGatewayTokenRequest{
		Handshake:       handshake,
		BridgeChannelID: "bridge_1",
		Now:             now.Add(2 * time.Second),
	}
	if _, err := service.MintGatewayToken(req); !errors.Is(err, ErrMissingTokenAudience) {
		t.Fatalf("MintGatewayToken() missing transcript error = %v, want %v", err, ErrMissingTokenAudience)
	}
	req.HandshakeTranscriptSHA256 = HandshakeTranscriptSHA256(handshake, "bridge_2")
	if _, err := service.MintGatewayToken(req); !errors.Is(err, ErrTokenAudience) {
		t.Fatalf("MintGatewayToken() wrong transcript error = %v, want %v", err, ErrTokenAudience)
	}
}

func TestHandshakeTranscriptSHA256StableVector(t *testing.T) {
	got := HandshakeTranscriptSHA256(Handshake{
		PluginID:           "com.example.plugin",
		SurfaceID:          "example.view",
		SurfaceInstanceID:  "surface_1",
		ActiveFingerprint:  "sha256:abc",
		BridgeNonce:        "nonce_1",
		AssetSessionNonce:  "asset_nonce_1",
		PluginStateVersion: 7,
		RevokeEpoch:        3,
		UIProtocolVersion:  "plugin-ui-v3",
	}, "bridge_channel_1")
	const want = "sha256:27cd2c3e0791b0f45d7c01bb3218da93c76f78638fe9e79be1fa56435a883f96"
	if got != want {
		t.Fatalf("HandshakeTranscriptSHA256() = %q, want %q", got, want)
	}
}

func TestSurfaceDisposeRevokesGatewayToken(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	bootstrap, gateway := mintTestGatewayToken(t, service, now)
	audience := surfaceAudienceFromBootstrap(bootstrap, "bridge_1")

	if !service.DisposeSurface(bootstrap.SurfaceInstanceID, now.Add(4*time.Second)) {
		t.Fatal("DisposeSurface() = false")
	}
	_, err := service.ValidateGatewayToken(gateway.GatewayToken, audience, testRevision(4), now.Add(5*time.Second))
	if !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("ValidateGatewayToken() error = %v, want %v", err, ErrTokenRevoked)
	}
}

func TestBoundSurfaceDisposeRequiresGenerationBinding(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	bootstrap, _ := mintTestGatewayToken(t, service, now)

	err := service.DisposeBoundSurface(DisposeSurfaceRequest{
		SurfaceInstanceID:    bootstrap.SurfaceInstanceID,
		OwnerSessionHash:     bootstrap.OwnerSessionHash,
		OwnerUserHash:        bootstrap.OwnerUserHash,
		SessionChannelIDHash: bootstrap.SessionChannelIDHash,
		Now:                  now.Add(4 * time.Second),
	})
	if !errors.Is(err, ErrMissingTokenAudience) {
		t.Fatalf("DisposeBoundSurface() without generation binding error = %v, want %v", err, ErrMissingTokenAudience)
	}
}

func TestStaleSurfaceGenerationCannotDisposeReplacement(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	request := testOpenSurfaceRequest(now)
	first, err := service.OpenSurface(request)
	if err != nil {
		t.Fatal(err)
	}
	request.ActiveFingerprint = "sha256:replacement"
	request.Revision.ManagementRevision++
	request.Now = now.Add(time.Second)
	replacement, err := service.OpenSurface(request)
	if err != nil {
		t.Fatal(err)
	}

	dispose := func(bridgeNonce string) error {
		return service.DisposeBoundSurface(DisposeSurfaceRequest{
			SurfaceInstanceID:    request.SurfaceInstanceID,
			BridgeNonce:          bridgeNonce,
			OwnerSessionHash:     request.OwnerSessionHash,
			OwnerUserHash:        request.OwnerUserHash,
			SessionChannelIDHash: request.SessionChannelIDHash,
			Now:                  now.Add(2 * time.Second),
		})
	}
	if err := dispose(first.BridgeNonce); !errors.Is(err, ErrTokenAudience) {
		t.Fatalf("stale DisposeBoundSurface() error = %v, want %v", err, ErrTokenAudience)
	}
	if err := dispose(replacement.BridgeNonce); err != nil {
		t.Fatalf("replacement DisposeBoundSurface() error = %v", err)
	}
}

func TestSurfaceRevokePluginDropsSessionsAndTokens(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	bootstrap, gateway := mintTestGatewayToken(t, service, now)
	audience := surfaceAudienceFromBootstrap(bootstrap, "bridge_1")

	if revoked, err := service.RevokePlugin(audience.PluginInstanceID, 0, now.Add(4*time.Second)); err != nil || revoked == 0 {
		t.Fatal("RevokePlugin() revoked no tokens")
	}
	if _, err := service.ValidateGatewayToken(gateway.GatewayToken, audience, testRevision(4), now.Add(5*time.Second)); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("ValidateGatewayToken() after plugin revoke error = %v, want %v", err, ErrTokenRevoked)
	}
	if _, err := service.ExchangeAssetTicket(exchangeAssetTicketRequest(bootstrap, now.Add(6*time.Second))); !errors.Is(err, ErrSurfaceSessionNotFound) {
		t.Fatalf("ExchangeAssetTicket() after plugin revoke error = %v, want %v", err, ErrSurfaceSessionNotFound)
	}
}

func TestSurfaceScopeRevocationMatchesOwnerAndChannel(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	target, err := service.OpenSurface(testOpenSurfaceRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	siblingRequest := testOpenSurfaceRequest(now)
	siblingRequest.SurfaceInstanceID = "surface_sibling"
	siblingRequest.SessionChannelIDHash = "channel_sibling"
	sibling, err := service.OpenSurface(siblingRequest)
	if err != nil {
		t.Fatal(err)
	}
	otherRequest := testOpenSurfaceRequest(now)
	otherRequest.SurfaceInstanceID = "surface_other"
	otherRequest.OwnerSessionHash = "sess_other"
	other, err := service.OpenSurface(otherRequest)
	if err != nil {
		t.Fatal(err)
	}

	revoked, err := service.RevokeSurfaceScope(RevokeSurfaceScopeRequest{
		OwnerSessionHash:     target.OwnerSessionHash,
		SessionChannelIDHash: target.SessionChannelIDHash,
		Now:                  now.Add(time.Second),
	})
	if err != nil || revoked != 1 {
		t.Fatalf("RevokeSurfaceScope() = %d, %v, want 1", revoked, err)
	}
	if _, err := service.ExchangeAssetTicket(exchangeAssetTicketRequest(target, now.Add(2*time.Second))); !errors.Is(err, ErrSurfaceSessionNotFound) {
		t.Fatalf("target surface remained active: %v", err)
	}
	if _, err := service.ExchangeAssetTicket(exchangeAssetTicketRequest(sibling, now.Add(2*time.Second))); err != nil {
		t.Fatalf("sibling channel was revoked: %v", err)
	}
	if _, err := service.ExchangeAssetTicket(exchangeAssetTicketRequest(other, now.Add(2*time.Second))); err != nil {
		t.Fatalf("other owner was revoked: %v", err)
	}
	if _, err := service.RevokeSurfaceScope(RevokeSurfaceScopeRequest{}); !errors.Is(err, ErrMissingTokenAudience) {
		t.Fatalf("empty scope error = %v, want %v", err, ErrMissingTokenAudience)
	}
}

func TestConfirmationTokenBindsRequestHashAndConsumesOnce(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	audience := testSurfaceAudience("bridge_1")
	audience.ConfirmationID = "confirmation_1"
	audience.Method = "danger.run"
	audience.RequestHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	audience.PlanHash = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	audience.TargetDescriptorSHA256 = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
	result, err := service.MintConfirmationToken(MintConfirmationTokenRequest{
		PluginID:               audience.PluginID,
		PluginInstanceID:       audience.PluginInstanceID,
		PluginVersion:          audience.PluginVersion,
		ActiveFingerprint:      audience.ActiveFingerprint,
		SurfaceID:              audience.SurfaceID,
		SurfaceInstanceID:      audience.SurfaceInstanceID,
		EntryPath:              audience.EntryPath,
		EntrySHA256:            audience.EntrySHA256,
		AssetSessionNonce:      audience.AssetSessionNonce,
		RouteRole:              audience.RouteRole,
		ConfirmationID:         audience.ConfirmationID,
		OwnerSessionHash:       audience.OwnerSessionHash,
		OwnerUserHash:          audience.OwnerUserHash,
		SessionChannelIDHash:   audience.SessionChannelIDHash,
		BridgeChannelID:        audience.BridgeChannelID,
		RuntimeGenerationID:    audience.RuntimeGenerationID,
		Method:                 audience.Method,
		RequestHash:            audience.RequestHash,
		PlanHash:               audience.PlanHash,
		TargetDescriptorSHA256: audience.TargetDescriptorSHA256,
		Revision:               testRevision(4),
		Now:                    now,
	})
	if err != nil {
		t.Fatalf("MintConfirmationToken() error = %v", err)
	}
	if result.ConfirmationToken == "" || result.RequestHash != audience.RequestHash || result.PlanHash != audience.PlanHash {
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
	wrongAudience = audience
	wrongAudience.PlanHash = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	if _, err := service.ValidateConfirmationToken(ValidateConfirmationTokenRequest{
		ConfirmationToken: result.ConfirmationToken,
		Audience:          wrongAudience,
		Revision:          testRevision(4),
		Now:               now.Add(time.Second),
	}); !errors.Is(err, ErrTokenAudience) {
		t.Fatalf("ValidateConfirmationToken() wrong plan hash error = %v, want %v", err, ErrTokenAudience)
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

func TestConfirmationTokenCanBeConsumedByServerHeldTokenID(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	audience := testSurfaceAudience("bridge_1")
	audience.ConfirmationID = "confirmation_by_id"
	audience.Method = "danger.run"
	audience.RequestHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	audience.PlanHash = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	audience.TargetDescriptorSHA256 = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
	result, err := service.MintConfirmationToken(MintConfirmationTokenRequest{
		PluginID:               audience.PluginID,
		PluginInstanceID:       audience.PluginInstanceID,
		PluginVersion:          audience.PluginVersion,
		ActiveFingerprint:      audience.ActiveFingerprint,
		SurfaceID:              audience.SurfaceID,
		SurfaceInstanceID:      audience.SurfaceInstanceID,
		EntryPath:              audience.EntryPath,
		EntrySHA256:            audience.EntrySHA256,
		AssetSessionNonce:      audience.AssetSessionNonce,
		RouteRole:              audience.RouteRole,
		ConfirmationID:         audience.ConfirmationID,
		OwnerSessionHash:       audience.OwnerSessionHash,
		OwnerUserHash:          audience.OwnerUserHash,
		SessionChannelIDHash:   audience.SessionChannelIDHash,
		BridgeChannelID:        audience.BridgeChannelID,
		RuntimeGenerationID:    audience.RuntimeGenerationID,
		Method:                 audience.Method,
		RequestHash:            audience.RequestHash,
		PlanHash:               audience.PlanHash,
		TargetDescriptorSHA256: audience.TargetDescriptorSHA256,
		Revision:               testRevision(4),
		Now:                    now,
	})
	if err != nil {
		t.Fatalf("MintConfirmationToken() error = %v", err)
	}
	if _, err := service.ValidateConfirmationTokenID(ValidateConfirmationTokenIDRequest{
		ConfirmationTokenID: result.ConfirmationTokenID,
		Audience:            audience,
		Revision:            testRevision(4),
		Now:                 now.Add(time.Second),
	}); err != nil {
		t.Fatalf("ValidateConfirmationTokenID() error = %v", err)
	}
	if _, err := service.ValidateConfirmationTokenID(ValidateConfirmationTokenIDRequest{
		ConfirmationTokenID: result.ConfirmationTokenID,
		Audience:            audience,
		Revision:            testRevision(4),
		Now:                 now.Add(2 * time.Second),
	}); !errors.Is(err, ErrTokenReplay) {
		t.Fatalf("ValidateConfirmationTokenID() replay error = %v, want %v", err, ErrTokenReplay)
	}
}

func TestConfirmationTokenTTLIsClamped(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	audience := testSurfaceAudience("bridge_1")
	audience.ConfirmationID = "confirmation_ttl"
	audience.Method = "danger.run"
	audience.RequestHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	audience.PlanHash = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	audience.TargetDescriptorSHA256 = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
	result, err := service.MintConfirmationToken(MintConfirmationTokenRequest{
		PluginID:               audience.PluginID,
		PluginInstanceID:       audience.PluginInstanceID,
		PluginVersion:          audience.PluginVersion,
		ActiveFingerprint:      audience.ActiveFingerprint,
		SurfaceID:              audience.SurfaceID,
		SurfaceInstanceID:      audience.SurfaceInstanceID,
		EntryPath:              audience.EntryPath,
		EntrySHA256:            audience.EntrySHA256,
		AssetSessionNonce:      audience.AssetSessionNonce,
		RouteRole:              audience.RouteRole,
		ConfirmationID:         audience.ConfirmationID,
		OwnerSessionHash:       audience.OwnerSessionHash,
		OwnerUserHash:          audience.OwnerUserHash,
		SessionChannelIDHash:   audience.SessionChannelIDHash,
		BridgeChannelID:        audience.BridgeChannelID,
		RuntimeGenerationID:    audience.RuntimeGenerationID,
		Method:                 audience.Method,
		RequestHash:            audience.RequestHash,
		PlanHash:               audience.PlanHash,
		TargetDescriptorSHA256: audience.TargetDescriptorSHA256,
		Revision:               testRevision(4),
		ExpiresAt:              now.Add(time.Hour),
		Now:                    now,
	})
	if err != nil {
		t.Fatalf("MintConfirmationToken() error = %v", err)
	}
	if got := result.ExpiresAt.Sub(now); got != MaxConfirmationTTL {
		t.Fatalf("confirmation TTL = %s, want %s", got, MaxConfirmationTTL)
	}
}

func TestStreamTicketTTLIsClamped(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	audience := testSurfaceAudience("bridge_1")
	audience.StreamID = "stream_ttl"
	audience.OperationID = "operation_ttl"
	audience.StreamDirection = "read"
	audience.Method = "logs.tail"
	result, err := service.MintStreamTicket(MintStreamTicketRequest{
		PluginID:             audience.PluginID,
		PluginInstanceID:     audience.PluginInstanceID,
		PluginVersion:        audience.PluginVersion,
		ActiveFingerprint:    audience.ActiveFingerprint,
		SurfaceID:            audience.SurfaceID,
		SurfaceInstanceID:    audience.SurfaceInstanceID,
		EntryPath:            audience.EntryPath,
		EntrySHA256:          audience.EntrySHA256,
		AssetSessionNonce:    audience.AssetSessionNonce,
		RouteRole:            audience.RouteRole,
		OwnerSessionHash:     audience.OwnerSessionHash,
		OwnerUserHash:        audience.OwnerUserHash,
		SessionChannelIDHash: audience.SessionChannelIDHash,
		BridgeChannelID:      audience.BridgeChannelID,
		RuntimeGenerationID:  audience.RuntimeGenerationID,
		StreamID:             audience.StreamID,
		OperationID:          audience.OperationID,
		StreamDirection:      audience.StreamDirection,
		Method:               audience.Method,
		Revision:             testRevision(11),
		ExpiresAt:            now.Add(time.Hour),
		Now:                  now,
	})
	if err != nil {
		t.Fatalf("MintStreamTicket() error = %v", err)
	}
	if got := result.ExpiresAt.Sub(now); got != MaxStreamTicketTTL {
		t.Fatalf("stream ticket TTL = %s, want %s", got, MaxStreamTicketTTL)
	}
}

func TestConfirmationTokenRequiresBoundMethodAndRequestHash(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	audience := testSurfaceAudience("bridge_1")
	audience.ConfirmationID = "confirmation_1"
	audience.Method = "danger.run"
	audience.RequestHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	audience.PlanHash = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	audience.TargetDescriptorSHA256 = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
	req := MintConfirmationTokenRequest{
		PluginID:               audience.PluginID,
		PluginInstanceID:       audience.PluginInstanceID,
		PluginVersion:          audience.PluginVersion,
		ActiveFingerprint:      audience.ActiveFingerprint,
		SurfaceID:              audience.SurfaceID,
		SurfaceInstanceID:      audience.SurfaceInstanceID,
		EntryPath:              audience.EntryPath,
		EntrySHA256:            audience.EntrySHA256,
		AssetSessionNonce:      audience.AssetSessionNonce,
		RouteRole:              audience.RouteRole,
		ConfirmationID:         audience.ConfirmationID,
		OwnerSessionHash:       audience.OwnerSessionHash,
		OwnerUserHash:          audience.OwnerUserHash,
		SessionChannelIDHash:   audience.SessionChannelIDHash,
		BridgeChannelID:        audience.BridgeChannelID,
		RuntimeGenerationID:    audience.RuntimeGenerationID,
		Method:                 audience.Method,
		RequestHash:            audience.RequestHash,
		PlanHash:               audience.PlanHash,
		TargetDescriptorSHA256: audience.TargetDescriptorSHA256,
		Revision:               testRevision(4),
		Now:                    now,
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
	badPlanHash := req
	badPlanHash.PlanHash = "sha256:not-a-real-hash"
	if _, err := service.MintConfirmationToken(badPlanHash); !errors.Is(err, ErrTokenAudience) {
		t.Fatalf("MintConfirmationToken() invalid plan hash error = %v, want %v", err, ErrTokenAudience)
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
		PluginInstanceID:     "plugini_test",
		PluginID:             "com.example.worker",
		PluginVersion:        "1.2.3",
		ActiveFingerprint:    "sha256:package",
		SurfaceInstanceID:    "surface_runtime",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		BridgeChannelID:      "bridge_runtime",
		RuntimeInstanceID:    "runtime_1",
		RuntimeGenerationID:  "runtime_gen_1",
		RuntimeShardID:       "runtime_shard_a",
		IPCChannelID:         "ipc_1",
		ConnectionNonce:      "connection_nonce_1234567890",
		Method:               "worker.echo",
		Effect:               "read",
		Execution:            "sync",
		AuditCorrelationID:   "audit_worker_echo",
		TargetDescriptorHashes: []string{
			"method:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"worker:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		Limits:   RuntimeExecutionLeaseLimits{MemoryBytes: 65536, MaxPayloadBytes: 4096},
		Revision: revision,
		Now:      now,
	})
	if err != nil {
		t.Fatalf("MintRuntimeExecutionLease() error = %v", err)
	}
	if result.LeaseToken == "" || result.LeaseID == "" || result.LeaseNonce == "" || result.RuntimeGenerationID != "runtime_gen_1" {
		t.Fatalf("runtime lease result mismatch: %#v", result)
	}
	if !strings.HasPrefix(result.LeaseID, "lease_") || !strings.HasPrefix(result.TokenID, "rel_") || result.TokenID == result.LeaseID {
		t.Fatalf("runtime lease ids mismatch: lease_id=%q token_id=%q", result.LeaseID, result.TokenID)
	}
	if result.PluginID != "com.example.worker" ||
		result.PluginVersion != "1.2.3" ||
		result.ActiveFingerprint != "sha256:package" ||
		result.SurfaceInstanceID != "surface_runtime" ||
		result.OwnerSessionHash != "session_hash" ||
		result.OwnerUserHash != "user_hash" ||
		result.SessionChannelIDHash != "channel_hash" ||
		result.BridgeChannelID != "bridge_runtime" ||
		result.RuntimeInstanceID != "runtime_1" ||
		result.RuntimeShardID != "runtime_shard_a" ||
		result.IPCChannelID != "ipc_1" ||
		result.ConnectionNonce != "connection_nonce_1234567890" ||
		result.Method != "worker.echo" ||
		result.Effect != "read" ||
		result.Execution != "sync" ||
		result.AuditCorrelationID != "audit_worker_echo" ||
		result.PolicyRevision != revision.PolicyRevision ||
		result.ManagementRevision != revision.ManagementRevision ||
		result.RevokeEpoch != revision.RevokeEpoch ||
		result.IssuedAtUnixMillis != unixMillis(result.IssuedAt) ||
		result.ExpiresAtUnixMillis != unixMillis(result.ExpiresAt) ||
		len(result.TargetDescriptorHashes) != 2 ||
		result.Limits.MemoryBytes != 65536 ||
		result.Limits.MaxPayloadBytes != 4096 {
		t.Fatalf("runtime lease metadata mismatch: %#v", result)
	}

	managerRecordAudience := Audience{
		PluginID:             "com.example.worker",
		PluginInstanceID:     "plugini_test",
		PluginVersion:        "1.2.3",
		ActiveFingerprint:    "sha256:package",
		SurfaceInstanceID:    "surface_runtime",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		BridgeChannelID:      "bridge_runtime",
		RuntimeInstanceID:    "runtime_1",
		RuntimeGenerationID:  "runtime_gen_1",
		RuntimeShardID:       "runtime_shard_a",
		IPCChannelID:         "ipc_1",
		ConnectionNonce:      "connection_nonce_1234567890",
		AuditCorrelationID:   "audit_worker_echo",
		Method:               "worker.echo",
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
		PluginInstanceID:   "plugini_test",
		ActiveFingerprint:  "sha256:package",
		Method:             "worker.echo",
		Execution:          "sync",
		AuditCorrelationID: "audit_runtime_required",
		Revision:           testRevision(8),
		Now:                testNow(),
	}
	if _, err := service.MintRuntimeExecutionLease(req); !errors.Is(err, ErrMissingTokenAudience) {
		t.Fatalf("MintRuntimeExecutionLease() missing generation error = %v, want %v", err, ErrMissingTokenAudience)
	}
	req.RuntimeGenerationID = "runtime_gen_1"
	req.RuntimeInstanceID = "runtime_1"
	req.IPCChannelID = "ipc_1"
	req.ConnectionNonce = "connection_nonce_1234567890"
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
		RuntimeInstanceID:   "runtime_1",
		RuntimeGenerationID: "runtime_gen_1",
		IPCChannelID:        "ipc_1",
		ConnectionNonce:     "connection_nonce_1234567890",
		Method:              "worker.echo",
		Execution:           "sync",
		AuditCorrelationID:  "audit_runtime_ttl",
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
	audience.OperationID = "operation_logs_1"
	audience.StreamDirection = "read"
	audience.Method = "logs.tail"
	result, err := service.MintStreamTicket(MintStreamTicketRequest{
		PluginID:             audience.PluginID,
		PluginInstanceID:     audience.PluginInstanceID,
		PluginVersion:        audience.PluginVersion,
		ActiveFingerprint:    audience.ActiveFingerprint,
		SurfaceID:            audience.SurfaceID,
		SurfaceInstanceID:    audience.SurfaceInstanceID,
		EntryPath:            audience.EntryPath,
		EntrySHA256:          audience.EntrySHA256,
		AssetSessionNonce:    audience.AssetSessionNonce,
		RouteRole:            audience.RouteRole,
		OwnerSessionHash:     audience.OwnerSessionHash,
		OwnerUserHash:        audience.OwnerUserHash,
		SessionChannelIDHash: audience.SessionChannelIDHash,
		BridgeChannelID:      audience.BridgeChannelID,
		RuntimeGenerationID:  audience.RuntimeGenerationID,
		StreamID:             audience.StreamID,
		OperationID:          audience.OperationID,
		StreamDirection:      audience.StreamDirection,
		Method:               audience.Method,
		Revision:             testRevision(11),
		Now:                  now,
	})
	if err != nil {
		t.Fatalf("MintStreamTicket() error = %v", err)
	}
	if result.StreamTicket == "" || result.StreamID != audience.StreamID || result.OperationID != audience.OperationID || result.Direction != "read" {
		t.Fatalf("stream ticket result mismatch: %#v", result)
	}

	wrongAudience := audience
	wrongAudience.OperationID = "operation_logs_other"
	if _, err := service.ValidateStreamTicket(ValidateStreamTicketRequest{
		StreamTicket: result.StreamTicket,
		Audience:     wrongAudience,
		Revision:     testRevision(11),
		Now:          now.Add(time.Second),
	}); !errors.Is(err, ErrTokenAudience) {
		t.Fatalf("ValidateStreamTicket() wrong operation error = %v, want %v", err, ErrTokenAudience)
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

func TestStreamTicketRejectsExpiredAndAudienceMismatches(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	now := testNow()
	audience := testSurfaceAudience("bridge_1")
	audience.StreamID = "stream_logs_1"
	audience.OperationID = "operation_logs_1"
	audience.StreamDirection = "read"
	audience.Method = "logs.tail"

	expiring, err := service.MintStreamTicket(MintStreamTicketRequest{
		PluginID:             audience.PluginID,
		PluginInstanceID:     audience.PluginInstanceID,
		PluginVersion:        audience.PluginVersion,
		ActiveFingerprint:    audience.ActiveFingerprint,
		SurfaceID:            audience.SurfaceID,
		SurfaceInstanceID:    audience.SurfaceInstanceID,
		EntryPath:            audience.EntryPath,
		EntrySHA256:          audience.EntrySHA256,
		AssetSessionNonce:    audience.AssetSessionNonce,
		RouteRole:            audience.RouteRole,
		OwnerSessionHash:     audience.OwnerSessionHash,
		OwnerUserHash:        audience.OwnerUserHash,
		SessionChannelIDHash: audience.SessionChannelIDHash,
		BridgeChannelID:      audience.BridgeChannelID,
		RuntimeGenerationID:  audience.RuntimeGenerationID,
		StreamID:             audience.StreamID,
		OperationID:          audience.OperationID,
		StreamDirection:      audience.StreamDirection,
		Method:               audience.Method,
		Revision:             testRevision(11),
		ExpiresAt:            now.Add(2 * time.Second),
		Now:                  now,
	})
	if err != nil {
		t.Fatalf("MintStreamTicket() error = %v", err)
	}
	if _, err := service.ValidateStreamTicket(ValidateStreamTicketRequest{
		StreamTicket: expiring.StreamTicket,
		Audience:     audience,
		Revision:     testRevision(11),
		Now:          now.Add(3 * time.Second),
	}); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("ValidateStreamTicket() expired error = %v, want %v", err, ErrTokenExpired)
	}

	tests := []struct {
		name   string
		mutate func(Audience) Audience
	}{
		{
			name: "wrong surface",
			mutate: func(audience Audience) Audience {
				audience.SurfaceInstanceID = "surface_other"
				return audience
			},
		},
		{
			name: "wrong fingerprint",
			mutate: func(audience Audience) Audience {
				audience.ActiveFingerprint = "sha256:other"
				return audience
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := service.MintStreamTicket(MintStreamTicketRequest{
				PluginID:             audience.PluginID,
				PluginInstanceID:     audience.PluginInstanceID,
				PluginVersion:        audience.PluginVersion,
				ActiveFingerprint:    audience.ActiveFingerprint,
				SurfaceID:            audience.SurfaceID,
				SurfaceInstanceID:    audience.SurfaceInstanceID,
				EntryPath:            audience.EntryPath,
				EntrySHA256:          audience.EntrySHA256,
				AssetSessionNonce:    audience.AssetSessionNonce,
				RouteRole:            audience.RouteRole,
				OwnerSessionHash:     audience.OwnerSessionHash,
				OwnerUserHash:        audience.OwnerUserHash,
				SessionChannelIDHash: audience.SessionChannelIDHash,
				BridgeChannelID:      audience.BridgeChannelID,
				RuntimeGenerationID:  audience.RuntimeGenerationID,
				StreamID:             audience.StreamID,
				OperationID:          audience.OperationID,
				StreamDirection:      audience.StreamDirection,
				Method:               audience.Method,
				Revision:             testRevision(11),
				Now:                  now,
			})
			if err != nil {
				t.Fatalf("MintStreamTicket() error = %v", err)
			}
			if _, err := service.ValidateStreamTicket(ValidateStreamTicketRequest{
				StreamTicket: result.StreamTicket,
				Audience:     tc.mutate(audience),
				Revision:     testRevision(11),
				Now:          now.Add(time.Second),
			}); !errors.Is(err, ErrTokenAudience) {
				t.Fatalf("ValidateStreamTicket() audience error = %v, want %v", err, ErrTokenAudience)
			}
		})
	}
}

func TestStreamTicketRequiresStreamDirectionAndMethod(t *testing.T) {
	service := NewSurfaceTokenService(nil, SurfaceTokenOptions{})
	audience := testSurfaceAudience("bridge_1")
	req := MintStreamTicketRequest{
		PluginInstanceID:     audience.PluginInstanceID,
		ActiveFingerprint:    audience.ActiveFingerprint,
		SurfaceID:            audience.SurfaceID,
		SurfaceInstanceID:    audience.SurfaceInstanceID,
		EntryPath:            audience.EntryPath,
		OwnerSessionHash:     audience.OwnerSessionHash,
		OwnerUserHash:        audience.OwnerUserHash,
		SessionChannelIDHash: audience.SessionChannelIDHash,
		BridgeChannelID:      audience.BridgeChannelID,
		StreamID:             "stream_logs_1",
		OperationID:          "operation_logs_1",
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
	missingOperation := req
	missingOperation.OperationID = ""
	if _, err := service.MintStreamTicket(missingOperation); !errors.Is(err, ErrMissingTokenAudience) {
		t.Fatalf("MintStreamTicket() missing operation error = %v, want %v", err, ErrMissingTokenAudience)
	}
}

func mintTestGatewayToken(t *testing.T, service *SurfaceTokenService, now time.Time) (SurfaceBootstrap, GatewayTokenResult) {
	t.Helper()
	bootstrap, err := service.OpenSurface(testOpenSurfaceRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	assetSession, err := service.ExchangeAssetTicket(exchangeAssetTicketRequest(bootstrap, now.Add(time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	markTestSurfacePrepared(t, service, bootstrap, assetSession, now.Add(time.Second))
	gateway, err := service.MintGatewayToken(MintGatewayTokenRequest{
		Handshake:                 handshakeFromBootstrap(bootstrap),
		BridgeChannelID:           "bridge_1",
		HandshakeTranscriptSHA256: HandshakeTranscriptSHA256(handshakeFromBootstrap(bootstrap), "bridge_1"),
		Now:                       now.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	return bootstrap, gateway
}

func markTestSurfacePrepared(t *testing.T, service *SurfaceTokenService, bootstrap SurfaceBootstrap, assetSession AssetSessionResult, now time.Time) {
	t.Helper()
	if err := service.MarkSurfacePrepared(MarkSurfacePreparedRequest{
		SurfaceInstanceID:    bootstrap.SurfaceInstanceID,
		AssetSessionID:       assetSession.AssetSessionID,
		BridgeNonce:          bootstrap.BridgeNonce,
		OwnerSessionHash:     bootstrap.OwnerSessionHash,
		OwnerUserHash:        bootstrap.OwnerUserHash,
		SessionChannelIDHash: bootstrap.SessionChannelIDHash,
		Now:                  now,
	}); err != nil {
		t.Fatalf("MarkSurfacePrepared() error = %v", err)
	}
}

func testOpenSurfaceRequest(now time.Time) OpenSurfaceRequest {
	return OpenSurfaceRequest{
		PluginID:             "com.example.plugin",
		PluginInstanceID:     "plugini_test",
		PluginVersion:        "1.2.3",
		SurfaceID:            "main.view",
		SurfaceInstanceID:    "surface_test",
		ActiveFingerprint:    "sha256:package",
		EntryPath:            "ui/index.html",
		EntrySHA256:          "sha256:entry",
		RouteRole:            "trusted_parent",
		RuntimeGenerationID:  "runtime_gen_1",
		OwnerSessionHash:     "sess_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		Revision:             testRevision(4),
		Now:                  now,
	}
}

func handshakeFromBootstrap(bootstrap SurfaceBootstrap) Handshake {
	return Handshake{
		PluginID:           bootstrap.PluginID,
		SurfaceID:          bootstrap.SurfaceID,
		SurfaceInstanceID:  bootstrap.SurfaceInstanceID,
		ActiveFingerprint:  bootstrap.ActiveFingerprint,
		BridgeNonce:        bootstrap.BridgeNonce,
		AssetSessionNonce:  bootstrap.AssetSessionNonce,
		PluginStateVersion: bootstrap.PluginStateVersion,
		RevokeEpoch:        bootstrap.RevokeEpoch,
		UIProtocolVersion:  "plugin-ui-v3",
	}
}

func exchangeAssetTicketRequest(bootstrap SurfaceBootstrap, now time.Time) ExchangeAssetTicketRequest {
	return ExchangeAssetTicketRequest{
		SurfaceInstanceID:    bootstrap.SurfaceInstanceID,
		AssetTicket:          bootstrap.AssetTicket,
		OwnerSessionHash:     bootstrap.OwnerSessionHash,
		OwnerUserHash:        bootstrap.OwnerUserHash,
		SessionChannelIDHash: bootstrap.SessionChannelIDHash,
		Now:                  now,
	}
}

func testSurfaceAudience(bridgeChannelID string) Audience {
	audience := testAudience()
	audience.BridgeChannelID = bridgeChannelID
	return audience
}

func surfaceAudienceFromBootstrap(bootstrap SurfaceBootstrap, bridgeChannelID string) Audience {
	return Audience{
		PluginID:             bootstrap.PluginID,
		PluginInstanceID:     bootstrap.PluginInstanceID,
		PluginVersion:        bootstrap.PluginVersion,
		ActiveFingerprint:    bootstrap.ActiveFingerprint,
		SurfaceID:            bootstrap.SurfaceID,
		SurfaceInstanceID:    bootstrap.SurfaceInstanceID,
		EntryPath:            bootstrap.EntryPath,
		EntrySHA256:          bootstrap.EntrySHA256,
		AssetSessionNonce:    bootstrap.AssetSessionNonce,
		RouteRole:            "trusted_parent",
		OwnerSessionHash:     bootstrap.OwnerSessionHash,
		OwnerUserHash:        bootstrap.OwnerUserHash,
		SessionChannelIDHash: bootstrap.SessionChannelIDHash,
		BridgeChannelID:      bridgeChannelID,
		RuntimeGenerationID:  bootstrap.RuntimeGenerationID,
	}
}
