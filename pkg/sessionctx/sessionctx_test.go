package sessionctx

import (
	"context"
	"errors"
	"testing"
)

func TestContextResourceScope(t *testing.T) {
	session := Context{
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		OwnerEnvHash:         "env_hash",
		SessionChannelIDHash: "channel_hash",
	}

	userScope, err := session.ResourceScope(ScopeUser)
	if err != nil {
		t.Fatal(err)
	}
	if userScope != (ResourceScope{Kind: ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"}) {
		t.Fatalf("user scope = %#v", userScope)
	}

	environmentScope, err := session.ResourceScope(ScopeEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	if environmentScope != (ResourceScope{Kind: ScopeEnvironment, OwnerEnvHash: "env_hash"}) {
		t.Fatalf("environment scope = %#v", environmentScope)
	}
}

func TestResourceScopeValidationAndMatching(t *testing.T) {
	validUser := ResourceScope{Kind: ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"}
	validEnvironment := ResourceScope{Kind: ScopeEnvironment, OwnerEnvHash: "env_hash"}

	for name, scope := range map[string]ResourceScope{
		"unknown kind":                {Kind: "global", OwnerEnvHash: "env_hash"},
		"missing environment owner":   {Kind: ScopeEnvironment},
		"invalid environment owner":   {Kind: ScopeEnvironment, OwnerEnvHash: " env_hash "},
		"missing user owner":          {Kind: ScopeUser, OwnerEnvHash: "env_hash"},
		"environment with user owner": {Kind: ScopeEnvironment, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := scope.Validate(); !errors.Is(err, ErrInvalidResourceScope) {
				t.Fatalf("Validate() error = %v, want ErrInvalidResourceScope", err)
			}
			if scope.Valid() {
				t.Fatalf("Valid() = true for %#v", scope)
			}
		})
	}

	if !validUser.Matches(validUser) || !validEnvironment.Matches(validEnvironment) {
		t.Fatal("valid resource scopes did not match themselves")
	}
	if validUser.Matches(validEnvironment) {
		t.Fatal("user scope matched environment scope")
	}
	if validUser.Matches(ResourceScope{Kind: ScopeUser, OwnerEnvHash: "env_other", OwnerUserHash: "user_hash"}) {
		t.Fatal("scope matched a different environment owner")
	}
	if validUser.Matches(ResourceScope{Kind: ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_other"}) {
		t.Fatal("scope matched a different user owner")
	}
}

func TestContextResourceScopeRejectsInvalidSession(t *testing.T) {
	if _, err := (Context{}).ResourceScope(ScopeUser); !errors.Is(err, ErrSessionRequired) {
		t.Fatalf("ResourceScope() error = %v, want ErrSessionRequired", err)
	}
	if _, err := Require(context.Background()); !errors.Is(err, ErrSessionRequired) {
		t.Fatalf("Require() error = %v, want ErrSessionRequired", err)
	}
}
