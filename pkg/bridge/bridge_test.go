package bridge

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAssetTicketConsumesOnce(t *testing.T) {
	manager := NewTokenManager()
	now := testNow()
	audience := testAudience()
	revision := testRevision(7)
	minted, err := manager.Mint(MintRequest{
		Kind:      TokenKindAssetTicket,
		Audience:  audience,
		Revision:  revision,
		ExpiresAt: now.Add(time.Minute),
		Now:       now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if minted.Use != TokenUseSingleUse {
		t.Fatalf("Use = %s", minted.Use)
	}

	record, err := manager.Validate(ValidateRequest{
		Kind:     TokenKindAssetTicket,
		Token:    minted.Token,
		Audience: audience,
		Revision: revision,
		Now:      now.Add(time.Second),
		Consume:  true,
	})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !record.Consumed || record.ConsumedAt == nil {
		t.Fatalf("record was not consumed: %#v", record)
	}

	_, err = manager.Validate(ValidateRequest{
		Kind:     TokenKindAssetTicket,
		Token:    minted.Token,
		Audience: audience,
		Revision: revision,
		Now:      now.Add(2 * time.Second),
		Consume:  true,
	})
	if !errors.Is(err, ErrTokenReplay) {
		t.Fatalf("Validate() replay error = %v, want %v", err, ErrTokenReplay)
	}
}

func TestTokenExpires(t *testing.T) {
	manager := NewTokenManager()
	now := testNow()
	minted, err := manager.Mint(MintRequest{
		Kind:      TokenKindAssetTicket,
		Audience:  testAudience(),
		Revision:  testRevision(1),
		ExpiresAt: now.Add(time.Second),
		Now:       now,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = manager.Validate(ValidateRequest{
		Kind:     TokenKindAssetTicket,
		Token:    minted.Token,
		Audience: minted.Audience,
		Revision: minted.Revision,
		Now:      now.Add(time.Second),
		Consume:  true,
	})
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrTokenExpired)
	}
}

func TestGatewayTokenBindsSingleBridgeChannel(t *testing.T) {
	manager := NewTokenManager()
	now := testNow()
	audience := testAudience()
	audience.BridgeChannelID = "bridge_a"
	revision := testRevision(3)
	minted, err := manager.Mint(MintRequest{
		Kind:      TokenKindPluginGatewayToken,
		Audience:  audience,
		Revision:  revision,
		ExpiresAt: now.Add(10 * time.Minute),
		Now:       now,
	})
	if err != nil {
		t.Fatal(err)
	}

	record, err := manager.Validate(ValidateRequest{
		Kind:     TokenKindPluginGatewayToken,
		Token:    minted.Token,
		Audience: audience,
		Revision: revision,
		Now:      now.Add(time.Second),
		Bind:     &ChannelBinding{BridgeChannelID: "bridge_a"},
	})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if record.BoundBridgeChannelID != "bridge_a" {
		t.Fatalf("BoundBridgeChannelID = %q", record.BoundBridgeChannelID)
	}

	_, err = manager.Validate(ValidateRequest{
		Kind:     TokenKindPluginGatewayToken,
		Token:    minted.Token,
		Audience: audience,
		Revision: revision,
		Now:      now.Add(2 * time.Second),
		Bind:     &ChannelBinding{BridgeChannelID: "bridge_b"},
	})
	if !errors.Is(err, ErrTokenAlreadyBound) {
		t.Fatalf("Validate() channel mismatch error = %v, want %v", err, ErrTokenAlreadyBound)
	}
}

func TestAudienceAndRevisionMismatchFailClosed(t *testing.T) {
	manager := NewTokenManager()
	now := testNow()
	minted, err := manager.Mint(MintRequest{
		Kind:      TokenKindPluginGatewayToken,
		Audience:  testAudience(),
		Revision:  testRevision(2),
		ExpiresAt: now.Add(time.Minute),
		Now:       now,
	})
	if err != nil {
		t.Fatal(err)
	}

	wrongAudience := minted.Audience
	wrongAudience.SurfaceInstanceID = "surface_other"
	_, err = manager.Validate(ValidateRequest{
		Kind:     TokenKindPluginGatewayToken,
		Token:    minted.Token,
		Audience: wrongAudience,
		Revision: minted.Revision,
		Now:      now.Add(time.Second),
	})
	if !errors.Is(err, ErrTokenAudience) {
		t.Fatalf("Validate() audience error = %v, want %v", err, ErrTokenAudience)
	}

	wrongRevision := minted.Revision
	wrongRevision.RevokeEpoch++
	_, err = manager.Validate(ValidateRequest{
		Kind:     TokenKindPluginGatewayToken,
		Token:    minted.Token,
		Audience: minted.Audience,
		Revision: wrongRevision,
		Now:      now.Add(time.Second),
	})
	if !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("Validate() revision error = %v, want %v", err, ErrTokenRevoked)
	}
}

func TestRevokePluginInvalidatesOlderEpoch(t *testing.T) {
	manager := NewTokenManager()
	now := testNow()
	oldRevision := testRevision(4)
	newRevision := testRevision(5)
	oldToken, err := manager.Mint(MintRequest{
		Kind:      TokenKindPluginGatewayToken,
		Audience:  testAudience(),
		Revision:  oldRevision,
		ExpiresAt: now.Add(time.Minute),
		Now:       now,
	})
	if err != nil {
		t.Fatal(err)
	}
	newToken, err := manager.Mint(MintRequest{
		Kind:      TokenKindPluginGatewayToken,
		Audience:  testAudience(),
		Revision:  newRevision,
		ExpiresAt: now.Add(time.Minute),
		Now:       now,
	})
	if err != nil {
		t.Fatal(err)
	}

	if revoked := manager.RevokePlugin("plugini_test", 5, now.Add(time.Second)); revoked != 1 {
		t.Fatalf("RevokePlugin() = %d, want 1", revoked)
	}
	_, err = manager.Validate(ValidateRequest{
		Kind:     TokenKindPluginGatewayToken,
		Token:    oldToken.Token,
		Audience: oldToken.Audience,
		Revision: oldRevision,
		Now:      now.Add(2 * time.Second),
	})
	if !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("Validate() old token error = %v, want %v", err, ErrTokenRevoked)
	}
	if _, err := manager.Validate(ValidateRequest{
		Kind:     TokenKindPluginGatewayToken,
		Token:    newToken.Token,
		Audience: newToken.Audience,
		Revision: newRevision,
		Now:      now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("Validate() new token error = %v", err)
	}
}

func TestSnapshotDoesNotExposeCleartextToken(t *testing.T) {
	manager := NewTokenManager()
	now := testNow()
	minted, err := manager.Mint(MintRequest{
		Kind:      TokenKindStreamTicket,
		Audience:  testAudience(),
		Revision:  testRevision(1),
		ExpiresAt: now.Add(time.Minute),
		Now:       now,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := manager.Snapshot()
	if len(snapshot) != 1 {
		t.Fatalf("Snapshot() length = %d", len(snapshot))
	}
	if snapshot[0].TokenHash == "" || !strings.HasPrefix(snapshot[0].TokenHash, "sha256:") {
		t.Fatalf("TokenHash = %q", snapshot[0].TokenHash)
	}
	if strings.Contains(snapshot[0].TokenHash, minted.Token) {
		t.Fatal("snapshot token hash contains cleartext token")
	}
}

func testNow() time.Time {
	return time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
}

func testAudience() Audience {
	return Audience{
		PluginInstanceID:     "plugini_test",
		ActiveFingerprint:    "sha256:package",
		SurfaceInstanceID:    "surface_test",
		OwnerSessionHash:     "sess_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
	}
}

func testRevision(revokeEpoch uint64) RevisionBinding {
	return RevisionBinding{
		PolicyRevision:     11,
		ManagementRevision: 12,
		RevokeEpoch:        revokeEpoch,
	}
}
