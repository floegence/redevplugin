package sessionctx

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestSessionScopeExactFourHashKey(t *testing.T) {
	session := Context{
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		OwnerEnvHash:         "env_hash",
		SessionChannelIDHash: "channel_hash",
	}
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatalf("SessionScope() error = %v", err)
	}
	if scope != (SessionScope{
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		OwnerEnvHash:         "env_hash",
		SessionChannelIDHash: "channel_hash",
	}) {
		t.Fatalf("SessionScope() = %#v", scope)
	}
	if !scope.Matches(scope) {
		t.Fatal("SessionScope.Matches(self) = false")
	}
	otherChannel := scope
	otherChannel.SessionChannelIDHash = "other_channel"
	if scope.Matches(otherChannel) {
		t.Fatal("SessionScope.Matches(other channel) = true")
	}
}

func TestSessionScopeRejectsMissingOrNonCanonicalHash(t *testing.T) {
	valid := SessionScope{
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		OwnerEnvHash:         "env_hash",
		SessionChannelIDHash: "channel_hash",
	}
	tests := []SessionScope{
		{},
		withSessionScopeField(valid, func(scope *SessionScope) { scope.OwnerSessionHash = "" }),
		withSessionScopeField(valid, func(scope *SessionScope) { scope.OwnerUserHash = " user_hash" }),
		withSessionScopeField(valid, func(scope *SessionScope) { scope.OwnerEnvHash = "env/hash" }),
		withSessionScopeField(valid, func(scope *SessionScope) { scope.SessionChannelIDHash = "channel hash" }),
	}
	for _, scope := range tests {
		if err := scope.Validate(); !errors.Is(err, ErrInvalidSessionScope) {
			t.Fatalf("Validate(%#v) error = %v, want ErrInvalidSessionScope", scope, err)
		}
	}
}

func TestSessionScopeAndContextJSONOmitPrivateHashes(t *testing.T) {
	session := Context{
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		OwnerEnvHash:         "env_hash",
		SessionChannelIDHash: "channel_hash",
	}
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatalf("SessionScope() error = %v", err)
	}
	for name, value := range map[string]any{"context": session, "scope": scope} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("Marshal(%s) error = %v", name, err)
		}
		if string(raw) != "{}" {
			t.Fatalf("Marshal(%s) = %s, want {}", name, raw)
		}
	}
}

func withSessionScopeField(scope SessionScope, mutate func(*SessionScope)) SessionScope {
	mutate(&scope)
	return scope
}
