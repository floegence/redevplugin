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

	wrongChannelAudience := audience
	wrongChannelAudience.BridgeChannelID = "bridge_b"
	_, err = manager.Validate(ValidateRequest{
		Kind:     TokenKindPluginGatewayToken,
		Token:    minted.Token,
		Audience: wrongChannelAudience,
		Revision: revision,
		Now:      now.Add(2 * time.Second),
		Bind:     &ChannelBinding{BridgeChannelID: "bridge_b"},
	})
	if !errors.Is(err, ErrTokenAlreadyBound) {
		t.Fatalf("Validate() channel mismatch error = %v, want %v", err, ErrTokenAlreadyBound)
	}
}

func TestMintUsesKindSpecificTokenIDNamespaces(t *testing.T) {
	cases := []struct {
		kind   TokenKind
		prefix string
		use    TokenUse
	}{
		{kind: TokenKindAssetTicket, prefix: "at_", use: TokenUseSingleUse},
		{kind: TokenKindAssetSession, prefix: "as_", use: TokenUseReusable},
		{kind: TokenKindPluginGatewayToken, prefix: "pgt_", use: TokenUseReusable},
		{kind: TokenKindConfirmationToken, prefix: "ct_", use: TokenUseSingleUse},
		{kind: TokenKindRuntimeExecutionLease, prefix: "rel_", use: TokenUseReusable},
		{kind: TokenKindHandleGrant, prefix: "hg_", use: TokenUseReusable},
		{kind: TokenKindStreamTicket, prefix: "st_", use: TokenUseSingleUse},
	}
	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			manager := NewTokenManager()
			now := testNow()
			minted, err := manager.Mint(MintRequest{
				Kind:      tc.kind,
				Audience:  testAudienceForTokenKind(tc.kind),
				Revision:  testRevision(8),
				ExpiresAt: now.Add(time.Minute),
				Now:       now,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(minted.TokenID, tc.prefix) {
				t.Fatalf("TokenID = %q, want prefix %q", minted.TokenID, tc.prefix)
			}
			if wantPrefix := string(tc.kind) + "." + minted.TokenID + "."; !strings.HasPrefix(minted.Token, wantPrefix) {
				t.Fatalf("Token = %q, want prefix %q", minted.Token, wantPrefix)
			}
			if minted.Use != tc.use {
				t.Fatalf("Use = %q, want %q", minted.Use, tc.use)
			}

			record, err := manager.Validate(ValidateRequest{
				Kind:     tc.kind,
				Token:    minted.Token,
				Audience: minted.Audience,
				Revision: minted.Revision,
				Now:      now.Add(time.Second),
				Consume:  tc.use == TokenUseSingleUse,
			})
			if err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if record.TokenID != minted.TokenID {
				t.Fatalf("record TokenID = %q, want %q", record.TokenID, minted.TokenID)
			}
			if record.Use != tc.use {
				t.Fatalf("record Use = %q, want %q", record.Use, tc.use)
			}
		})
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

func testAudienceForTokenKind(kind TokenKind) Audience {
	audience := testAudience()
	switch kind {
	case TokenKindPluginGatewayToken:
		audience.BridgeChannelID = "bridge_test"
	case TokenKindConfirmationToken:
		audience.BridgeChannelID = "bridge_test"
		audience.ConfirmationID = "confirm_test"
		audience.Method = "plugin.confirm"
		audience.RequestHash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		audience.PlanHash = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	case TokenKindRuntimeExecutionLease:
		audience.SurfaceInstanceID = ""
		audience.RuntimeGenerationID = "generation_test"
		audience.Method = "runtime.execute"
	case TokenKindHandleGrant:
		audience.SurfaceInstanceID = ""
		audience.RuntimeGenerationID = "generation_test"
		audience.HandleID = "handle_test"
		audience.Method = "handle.read"
	case TokenKindStreamTicket:
		audience.BridgeChannelID = "bridge_test"
		audience.StreamID = "stream_test"
		audience.StreamDirection = "duplex"
		audience.Method = "stream.open"
	}
	return audience
}

func testRevision(revokeEpoch uint64) RevisionBinding {
	return RevisionBinding{
		PolicyRevision:     11,
		ManagementRevision: 12,
		RevokeEpoch:        revokeEpoch,
	}
}
