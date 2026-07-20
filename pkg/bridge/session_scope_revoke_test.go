package bridge

import (
	"errors"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

func TestTokenManagerRevokeSessionScopeUsesExactIndexAndCountsKinds(t *testing.T) {
	manager := NewTokenManager()
	now := testNow()
	scope := sessionctx.SessionScope{
		OwnerSessionHash:     "sess_hash",
		OwnerUserHash:        "user_hash",
		OwnerEnvHash:         "env_hash",
		SessionChannelIDHash: "channel_hash",
	}
	kinds := []TokenKind{
		TokenKindAssetTicket,
		TokenKindAssetSession,
		TokenKindPluginGatewayToken,
		TokenKindConfirmationToken,
		TokenKindHandleGrant,
		TokenKindStreamTicket,
	}
	targets := make(map[TokenKind]MintedToken, len(kinds))
	siblings := make(map[TokenKind]MintedToken, len(kinds))
	for _, kind := range kinds {
		targetAudience := testAudienceForTokenKind(kind)
		target, err := manager.Mint(MintRequest{
			Kind: kind, Audience: targetAudience, Revision: testRevision(7), ExpiresAt: now.Add(time.Minute), Now: now,
		})
		if err != nil {
			t.Fatalf("Mint(%s target) error = %v", kind, err)
		}
		targets[kind] = target
		siblingAudience := testAudienceForTokenKind(kind)
		siblingAudience.SessionChannelIDHash = "channel_sibling"
		sibling, err := manager.Mint(MintRequest{
			Kind: kind, Audience: siblingAudience, Revision: testRevision(7), ExpiresAt: now.Add(time.Minute), Now: now,
		})
		if err != nil {
			t.Fatalf("Mint(%s sibling) error = %v", kind, err)
		}
		siblings[kind] = sibling
	}

	revoked, err := manager.RevokeSessionScope(scope, now.Add(time.Second))
	if err != nil {
		t.Fatalf("RevokeSessionScope() error = %v", err)
	}
	if revoked != (SessionTokenRevocationCounts{
		AssetTickets:        1,
		AssetSessions:       1,
		PluginGatewayTokens: 1,
		ConfirmationTokens:  1,
		HandleGrants:        1,
		StreamTickets:       1,
	}) {
		t.Fatalf("RevokeSessionScope() = %#v", revoked)
	}
	if manager.sessionRevokeScanned != uint64(len(kinds)) {
		t.Fatalf("session revoke scanned %d records, want %d affected records", manager.sessionRevokeScanned, len(kinds))
	}
	for _, kind := range kinds {
		if _, err := manager.Inspect(InspectRequest{Kind: kind, Token: targets[kind].Token, Now: now.Add(2 * time.Second)}); !errors.Is(err, ErrTokenRevoked) {
			t.Fatalf("Inspect(%s target) error = %v, want ErrTokenRevoked", kind, err)
		}
		if _, err := manager.Inspect(InspectRequest{Kind: kind, Token: siblings[kind].Token, Now: now.Add(2 * time.Second)}); err != nil {
			t.Fatalf("Inspect(%s sibling) error = %v", kind, err)
		}
	}
	second, err := manager.RevokeSessionScope(scope, now.Add(3*time.Second))
	if err != nil || second != (SessionTokenRevocationCounts{}) {
		t.Fatalf("RevokeSessionScope(replay) = %#v, %v", second, err)
	}
}

func TestSurfaceTokenServiceRevokeSessionScopePreservesSiblingChannel(t *testing.T) {
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
	scope := sessionctx.SessionScope{
		OwnerSessionHash:     target.OwnerSessionHash,
		OwnerUserHash:        target.OwnerUserHash,
		OwnerEnvHash:         target.OwnerEnvHash,
		SessionChannelIDHash: target.SessionChannelIDHash,
	}
	revoked, err := service.RevokeSessionScope(RevokeSessionScopeRequest{SessionScope: scope, Now: now.Add(time.Second)})
	if err != nil {
		t.Fatalf("RevokeSessionScope() error = %v", err)
	}
	if revoked.Surfaces != 1 || revoked.Tokens.AssetTickets != 1 {
		t.Fatalf("RevokeSessionScope() = %#v", revoked)
	}
	if service.sessionRevokeScanned != 1 {
		t.Fatalf("surface revoke scanned %d records, want 1 affected record", service.sessionRevokeScanned)
	}
	if _, err := service.ExchangeAssetTicket(exchangeAssetTicketRequest(target, now.Add(2*time.Second))); !errors.Is(err, ErrSurfaceSessionNotFound) {
		t.Fatalf("target surface remained active: %v", err)
	}
	if _, err := service.ExchangeAssetTicket(exchangeAssetTicketRequest(sibling, now.Add(2*time.Second))); err != nil {
		t.Fatalf("sibling channel was revoked: %v", err)
	}
}
