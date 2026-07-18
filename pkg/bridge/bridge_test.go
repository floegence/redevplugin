package bridge

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/sessionctx"
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

func TestTokenMintRejectsInvalidRevisionBindings(t *testing.T) {
	manager := NewTokenManager()
	now := testNow()
	base := MintRequest{
		Kind:      TokenKindAssetTicket,
		Audience:  testAudience(),
		Revision:  testRevision(7),
		ExpiresAt: now.Add(time.Minute),
		Now:       now,
	}
	for _, mutate := range []func(*RevisionBinding){
		func(revision *RevisionBinding) { revision.RevokeEpoch = 0 },
		func(revision *RevisionBinding) { revision.PolicyRevision = 1 << 53 },
		func(revision *RevisionBinding) { revision.ManagementRevision = 1 << 53 },
		func(revision *RevisionBinding) { revision.RevokeEpoch = 1 << 53 },
	} {
		req := base
		mutate(&req.Revision)
		if _, err := manager.Mint(req); !errors.Is(err, ErrTokenRevision) {
			t.Fatalf("Mint() revision %#v error = %v, want %v", req.Revision, err, ErrTokenRevision)
		}
	}
	if _, err := manager.RevokePlugin("env_hash", "plugini_test", 0, now); !errors.Is(err, ErrTokenRevision) {
		t.Fatalf("RevokePlugin() zero epoch error = %v, want %v", err, ErrTokenRevision)
	}
	for _, limits := range []Limits{{MaxTotalBytes: -1}, {MaxBytesPerSecond: 1 << 53}} {
		req := base
		req.Limits = limits
		if _, err := manager.Mint(req); !errors.Is(err, ErrTokenLimits) {
			t.Fatalf("Mint() limits %#v error = %v, want %v", limits, err, ErrTokenLimits)
		}
	}
}

func TestTokenMintRejectsNonCanonicalSessionOwnerHashes(t *testing.T) {
	manager := NewTokenManager()
	now := testNow()
	for _, mutate := range []func(*Audience){
		func(audience *Audience) { audience.OwnerEnvHash = "env/hash" },
		func(audience *Audience) { audience.OwnerUserHash = " user_hash" },
	} {
		audience := testAudience()
		mutate(&audience)
		if _, err := manager.Mint(MintRequest{
			Kind: TokenKindAssetTicket, Audience: audience, Revision: testRevision(7), ExpiresAt: now.Add(time.Minute), Now: now,
		}); !errors.Is(err, ErrTokenAudience) {
			t.Fatalf("Mint() audience %#v error = %v, want %v", audience, err, ErrTokenAudience)
		}
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

func TestMintPrunesExpiredTokenRecords(t *testing.T) {
	manager := NewTokenManager()
	now := testNow()
	first, err := manager.Mint(MintRequest{
		Kind:      TokenKindAssetTicket,
		Audience:  testAudience(),
		Revision:  testRevision(1),
		ExpiresAt: now.Add(time.Second),
		Now:       now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(manager.Snapshot()); got != 1 {
		t.Fatalf("Snapshot() length = %d, want 1", got)
	}

	secondAudience := testAudience()
	secondAudience.SurfaceInstanceID = "surface_second"
	if _, err := manager.Mint(MintRequest{
		Kind:      TokenKindAssetTicket,
		Audience:  secondAudience,
		Revision:  testRevision(1),
		ExpiresAt: now.Add(2 * time.Minute),
		Now:       now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	records := manager.Snapshot()
	if len(records) != 1 || records[0].TokenID == first.TokenID {
		t.Fatalf("Snapshot() = %#v, want only the unexpired token", records)
	}
}

func TestTokenManagerEnforcesGlobalAndPerPluginCapacity(t *testing.T) {
	now := testNow()
	t.Run("global capacity", func(t *testing.T) {
		manager := NewTokenManager(TokenManagerOptions{
			MaxRecords:          2,
			MaxRecordsPerPlugin: 2,
			MaxRevokeFloors:     2,
			MaxTTL:              time.Minute,
		})
		for i := 0; i < 2; i++ {
			audience := testAudienceForTokenKind(TokenKindPluginGatewayToken)
			audience.SurfaceInstanceID = "surface_" + string(rune('a'+i))
			if _, err := manager.Mint(MintRequest{
				Kind:      TokenKindPluginGatewayToken,
				Audience:  audience,
				Revision:  testRevision(1),
				ExpiresAt: now.Add(time.Minute),
				Now:       now,
			}); err != nil {
				t.Fatalf("Mint(%d) error = %v", i, err)
			}
		}
		audience := testAudienceForTokenKind(TokenKindPluginGatewayToken)
		audience.PluginInstanceID = "plugini_other"
		if _, err := manager.Mint(MintRequest{
			Kind:      TokenKindPluginGatewayToken,
			Audience:  audience,
			Revision:  testRevision(1),
			ExpiresAt: now.Add(time.Minute),
			Now:       now,
		}); !errors.Is(err, ErrTokenCapacity) {
			t.Fatalf("Mint(over global capacity) error = %v, want %v", err, ErrTokenCapacity)
		}
	})

	t.Run("per plugin capacity", func(t *testing.T) {
		manager := NewTokenManager(TokenManagerOptions{
			MaxRecords:          2,
			MaxRecordsPerPlugin: 1,
			MaxRevokeFloors:     2,
			MaxTTL:              time.Minute,
		})
		firstAudience := testAudienceForTokenKind(TokenKindPluginGatewayToken)
		mint := func(audience Audience) error {
			_, err := manager.Mint(MintRequest{
				Kind:      TokenKindPluginGatewayToken,
				Audience:  audience,
				Revision:  testRevision(1),
				ExpiresAt: now.Add(time.Minute),
				Now:       now,
			})
			return err
		}
		if err := mint(firstAudience); err != nil {
			t.Fatal(err)
		}
		firstAudience.SurfaceInstanceID = "surface_second"
		if err := mint(firstAudience); !errors.Is(err, ErrTokenPluginCapacity) {
			t.Fatalf("Mint(over plugin capacity) error = %v, want %v", err, ErrTokenPluginCapacity)
		}
		otherAudience := firstAudience
		otherAudience.PluginInstanceID = "plugini_other"
		if err := mint(otherAudience); err != nil {
			t.Fatalf("Mint(other plugin) error = %v", err)
		}
	})
}

func TestTokenManagerRejectsTTLAboveLimitAndReclaimsExpiredCapacity(t *testing.T) {
	now := testNow()
	manager := NewTokenManager(TokenManagerOptions{
		MaxRecords:          1,
		MaxRecordsPerPlugin: 1,
		MaxRevokeFloors:     1,
		MaxTTL:              time.Minute,
	})
	request := MintRequest{
		Kind:      TokenKindPluginGatewayToken,
		Audience:  testAudienceForTokenKind(TokenKindPluginGatewayToken),
		Revision:  testRevision(1),
		ExpiresAt: now.Add(time.Minute + time.Nanosecond),
		Now:       now,
	}
	if _, err := manager.Mint(request); !errors.Is(err, ErrTokenTTLExceeded) {
		t.Fatalf("Mint(over max TTL) error = %v, want %v", err, ErrTokenTTLExceeded)
	}
	request.ExpiresAt = now.Add(time.Second)
	if _, err := manager.Mint(request); err != nil {
		t.Fatal(err)
	}
	request.Now = now.Add(time.Second)
	request.ExpiresAt = request.Now.Add(time.Minute)
	if _, err := manager.Mint(request); err != nil {
		t.Fatalf("Mint(after expiry) error = %v", err)
	}
}

func TestTokenManagerIndexesTokenIDs(t *testing.T) {
	manager := NewTokenManager()
	now := testNow()
	minted, err := manager.Mint(MintRequest{
		Kind:      TokenKindPluginGatewayToken,
		Audience:  testAudienceForTokenKind(TokenKindPluginGatewayToken),
		Revision:  testRevision(1),
		ExpiresAt: now.Add(time.Minute),
		Now:       now,
	})
	if err != nil {
		t.Fatal(err)
	}
	key := tokenIDIndexKey(minted.Kind, minted.TokenID)
	if manager.idIndex[key] == "" {
		t.Fatalf("token id index missing key %q", key)
	}
	if !manager.RevokeTokenID(minted.Kind, minted.TokenID, now.Add(time.Second)) {
		t.Fatal("RevokeTokenID() = false, want true")
	}
}

func TestTokenManagerRevokeFloorCapacityFailsClosed(t *testing.T) {
	manager := NewTokenManager(TokenManagerOptions{
		MaxRecords:          4,
		MaxRecordsPerPlugin: 2,
		MaxRevokeFloors:     1,
		MaxTTL:              time.Minute,
	})
	now := testNow()
	if _, err := manager.RevokePlugin("env_hash", "plugini_first", 2, now); err != nil {
		t.Fatalf("RevokePlugin(first) error = %v", err)
	}
	if _, err := manager.RevokePlugin("env_hash", "plugini_second", 2, now); !errors.Is(err, ErrTokenRevokeFloorCapacity) {
		t.Fatalf("RevokePlugin(over floor capacity) error = %v, want %v", err, ErrTokenRevokeFloorCapacity)
	}
	audience := testAudienceForTokenKind(TokenKindPluginGatewayToken)
	audience.PluginInstanceID = "plugini_second"
	if _, err := manager.Mint(MintRequest{
		Kind:      TokenKindPluginGatewayToken,
		Audience:  audience,
		Revision:  testRevision(2),
		ExpiresAt: now.Add(time.Minute),
		Now:       now,
	}); !errors.Is(err, ErrTokenRevokeFloorCapacity) {
		t.Fatalf("Mint(after floor saturation) error = %v, want %v", err, ErrTokenRevokeFloorCapacity)
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
		{kind: TokenKindHandleGrant, prefix: "hg_", use: TokenUseReusable},
		{kind: TokenKindStreamTicket, prefix: "st_", use: TokenUseReusable},
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

func TestMintRejectsCallerOverrideOfKindSpecificUse(t *testing.T) {
	manager := NewTokenManager()
	now := testNow()
	if _, err := manager.Mint(MintRequest{
		Kind:      TokenKindAssetTicket,
		Use:       TokenUseReusable,
		Audience:  testAudienceForTokenKind(TokenKindAssetTicket),
		Revision:  testRevision(1),
		ExpiresAt: now.Add(time.Minute),
		Now:       now,
	}); err == nil {
		t.Fatal("Mint() accepted a reusable asset ticket")
	}
}

func TestNonHandleTokenAudienceRejectsResourceScope(t *testing.T) {
	manager := NewTokenManager()
	now := testNow()
	for _, kind := range []TokenKind{
		TokenKindAssetTicket,
		TokenKindAssetSession,
		TokenKindPluginGatewayToken,
		TokenKindConfirmationToken,
		TokenKindStreamTicket,
	} {
		t.Run(string(kind), func(t *testing.T) {
			for _, scopeCase := range []struct {
				name  string
				scope sessionctx.ResourceScope
			}{
				{name: "valid", scope: sessionctx.ResourceScope{
					Kind:          sessionctx.ScopeUser,
					OwnerEnvHash:  "env_injected",
					OwnerUserHash: "user_injected",
				}},
				{name: "partially populated", scope: sessionctx.ResourceScope{OwnerEnvHash: "env_injected"}},
			} {
				t.Run(scopeCase.name, func(t *testing.T) {
					audience := testAudienceForTokenKind(kind)
					audience.ResourceScope = scopeCase.scope
					if _, err := manager.Mint(MintRequest{
						Kind:      kind,
						Audience:  audience,
						Revision:  testRevision(1),
						ExpiresAt: now.Add(time.Minute),
						Now:       now,
					}); !errors.Is(err, ErrTokenAudience) {
						t.Fatalf("Mint() resource scope injection error = %v, want %v", err, ErrTokenAudience)
					}
				})
			}
		})
	}
}

func TestTokenPluginIndexKeyRejectsNonHandleResourceScopeOwnerInjection(t *testing.T) {
	audience := testAudienceForTokenKind(TokenKindPluginGatewayToken)
	audience.ResourceScope = sessionctx.ResourceScope{
		Kind:          sessionctx.ScopeUser,
		OwnerEnvHash:  "env_injected",
		OwnerUserHash: "user_injected",
	}
	if _, err := tokenPluginIndexKey(TokenKindPluginGatewayToken, audience); !errors.Is(err, ErrTokenAudience) {
		t.Fatalf("tokenPluginIndexKey() injection error = %v, want %v", err, ErrTokenAudience)
	}

	handleAudience := testAudienceForTokenKind(TokenKindHandleGrant)
	key, err := tokenPluginIndexKey(TokenKindHandleGrant, handleAudience)
	if err != nil {
		t.Fatal(err)
	}
	want, err := ownerPluginIndexKey(handleAudience.ResourceScope.OwnerEnvHash, handleAudience.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if key != want {
		t.Fatalf("handle grant plugin index key = %q, want %q", key, want)
	}
}

func TestAudienceAndRevisionMismatchFailClosed(t *testing.T) {
	manager := NewTokenManager()
	now := testNow()
	minted, err := manager.Mint(MintRequest{
		Kind:      TokenKindPluginGatewayToken,
		Audience:  testAudienceForTokenKind(TokenKindPluginGatewayToken),
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

	wrongEnvironment := minted.Audience
	wrongEnvironment.OwnerEnvHash = "env_other"
	_, err = manager.Validate(ValidateRequest{
		Kind:     TokenKindPluginGatewayToken,
		Token:    minted.Token,
		Audience: wrongEnvironment,
		Revision: minted.Revision,
		Now:      now.Add(time.Second),
	})
	if !errors.Is(err, ErrTokenAudience) {
		t.Fatalf("Validate() environment audience error = %v, want %v", err, ErrTokenAudience)
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
		Audience:  testAudienceForTokenKind(TokenKindPluginGatewayToken),
		Revision:  oldRevision,
		ExpiresAt: now.Add(time.Minute),
		Now:       now,
	})
	if err != nil {
		t.Fatal(err)
	}
	newToken, err := manager.Mint(MintRequest{
		Kind:      TokenKindPluginGatewayToken,
		Audience:  testAudienceForTokenKind(TokenKindPluginGatewayToken),
		Revision:  newRevision,
		ExpiresAt: now.Add(time.Minute),
		Now:       now,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherEnvironmentAudience := testAudienceForTokenKind(TokenKindPluginGatewayToken)
	otherEnvironmentAudience.OwnerEnvHash = "env_other"
	otherEnvironmentToken, err := manager.Mint(MintRequest{
		Kind:      TokenKindPluginGatewayToken,
		Audience:  otherEnvironmentAudience,
		Revision:  oldRevision,
		ExpiresAt: now.Add(time.Minute),
		Now:       now,
	})
	if err != nil {
		t.Fatal(err)
	}

	if revoked, err := manager.RevokePlugin("env_hash", "plugini_test", 5, now.Add(time.Second)); err != nil || revoked != 1 {
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
	if _, err := manager.Validate(ValidateRequest{
		Kind:     TokenKindPluginGatewayToken,
		Token:    otherEnvironmentToken.Token,
		Audience: otherEnvironmentAudience,
		Revision: oldRevision,
		Now:      now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("Validate() same plugin in another environment error = %v", err)
	}
}

func TestSnapshotDoesNotExposeCleartextToken(t *testing.T) {
	manager := NewTokenManager()
	now := testNow()
	minted, err := manager.Mint(MintRequest{
		Kind:      TokenKindStreamTicket,
		Audience:  testAudienceForTokenKind(TokenKindStreamTicket),
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
		PluginID:             "com.example.plugin",
		PluginInstanceID:     "plugini_test",
		PluginVersion:        "1.2.3",
		ActiveFingerprint:    "sha256:package",
		SurfaceID:            "com.example.plugin.view",
		SurfaceInstanceID:    "surface_test",
		EntryPath:            "ui/index.html",
		EntrySHA256:          "sha256:entry",
		AssetSessionNonce:    "asset_nonce_test",
		RouteRole:            RouteRoleTrustedParent,
		OwnerSessionHash:     "sess_hash",
		OwnerUserHash:        "user_hash",
		OwnerEnvHash:         "env_hash",
		SessionChannelIDHash: "channel_hash",
		RuntimeGenerationID:  "runtime_gen_test",
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
		audience.TargetDescriptorSHA256 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	case TokenKindHandleGrant:
		audience.PluginID = ""
		audience.PluginVersion = ""
		audience.EntrySHA256 = ""
		audience.AssetSessionNonce = ""
		audience.RouteRole = ""
		audience.SurfaceInstanceID = ""
		audience.RuntimeGenerationID = "generation_test"
		audience.HandleID = "handle_test"
		audience.Method = "handle.read"
		audience.ResourceScope = sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"}
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
