package sessionctx

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var ErrSessionRequired = errors.New("authenticated session is required")

var ErrInvalidResourceScope = errors.New("resource owner scope is invalid")

var ErrInvalidSessionScope = errors.New("session scope is invalid")

const OwnerScopeMigrationRequiredCode = "owner_scope_migration_required"

// ErrOwnerScopeMigrationRequired rejects persisted resources whose owner scope
// cannot be reconstructed without guessing.
var ErrOwnerScopeMigrationRequired = errors.New(OwnerScopeMigrationRequiredCode)

var ownerHashPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)

type ScopeKind string

const (
	ScopeUser        ScopeKind = "user"
	ScopeEnvironment ScopeKind = "environment"
)

// ResourceScope is the stable ownership boundary for persistent plugin data.
// Session and channel hashes are intentionally excluded: those values belong
// only to short-lived surfaces, operations, streams, and token audiences.
type ResourceScope struct {
	Kind          ScopeKind `json:"kind"`
	OwnerEnvHash  string    `json:"owner_env_hash"`
	OwnerUserHash string    `json:"owner_user_hash,omitempty"`
}

func (s ResourceScope) Validate() error {
	if s.Kind != ScopeUser && s.Kind != ScopeEnvironment {
		return fmt.Errorf("%w: kind must be user or environment", ErrInvalidResourceScope)
	}
	if !validOwnerHash(s.OwnerEnvHash) {
		return fmt.Errorf("%w: owner_env_hash is invalid", ErrInvalidResourceScope)
	}
	if s.Kind == ScopeUser {
		if !validOwnerHash(s.OwnerUserHash) {
			return fmt.Errorf("%w: owner_user_hash is invalid", ErrInvalidResourceScope)
		}
	} else if strings.TrimSpace(s.OwnerUserHash) != "" {
		return fmt.Errorf("%w: environment scope must not contain owner_user_hash", ErrInvalidResourceScope)
	}
	return nil
}

func (s ResourceScope) Valid() bool { return s.Validate() == nil }

func (s ResourceScope) Matches(other ResourceScope) bool {
	return s.Validate() == nil && other.Validate() == nil &&
		s.Kind == other.Kind &&
		s.OwnerEnvHash == other.OwnerEnvHash &&
		s.OwnerUserHash == other.OwnerUserHash
}

type Context struct {
	OwnerSessionHash     string `json:"-"`
	OwnerUserHash        string `json:"-"`
	OwnerEnvHash         string `json:"-"`
	SessionChannelIDHash string `json:"-"`
}

func (s Context) Valid() bool {
	return validOwnerHash(s.OwnerSessionHash) &&
		validOwnerHash(s.OwnerUserHash) &&
		validOwnerHash(s.OwnerEnvHash) &&
		validOwnerHash(s.SessionChannelIDHash)
}

// SessionScope is the exact ownership boundary for session capabilities. Its
// fields are deliberately excluded from JSON so authenticated owner identity
// cannot enter an HTTP or plugin-controlled payload by accident.
type SessionScope struct {
	OwnerSessionHash     string `json:"-"`
	OwnerUserHash        string `json:"-"`
	OwnerEnvHash         string `json:"-"`
	SessionChannelIDHash string `json:"-"`
}

func (s SessionScope) Validate() error {
	if !validOwnerHash(s.OwnerSessionHash) {
		return fmt.Errorf("%w: owner_session_hash is invalid", ErrInvalidSessionScope)
	}
	if !validOwnerHash(s.OwnerUserHash) {
		return fmt.Errorf("%w: owner_user_hash is invalid", ErrInvalidSessionScope)
	}
	if !validOwnerHash(s.OwnerEnvHash) {
		return fmt.Errorf("%w: owner_env_hash is invalid", ErrInvalidSessionScope)
	}
	if !validOwnerHash(s.SessionChannelIDHash) {
		return fmt.Errorf("%w: session_channel_id_hash is invalid", ErrInvalidSessionScope)
	}
	return nil
}

func (s SessionScope) Valid() bool { return s.Validate() == nil }

func (s SessionScope) Matches(other SessionScope) bool {
	return s.Valid() && other.Valid() && s == other
}

func (s Context) SessionScope() (SessionScope, error) {
	if !s.Valid() {
		return SessionScope{}, ErrSessionRequired
	}
	scope := SessionScope(s)
	if err := scope.Validate(); err != nil {
		return SessionScope{}, err
	}
	return scope, nil
}

func (s Context) ResourceScope(kind ScopeKind) (ResourceScope, error) {
	if !s.Valid() {
		return ResourceScope{}, ErrSessionRequired
	}
	scope := ResourceScope{Kind: kind, OwnerEnvHash: s.OwnerEnvHash}
	if kind == ScopeUser {
		scope.OwnerUserHash = s.OwnerUserHash
	}
	if err := scope.Validate(); err != nil {
		return ResourceScope{}, err
	}
	return scope, nil
}

type contextKey struct{}

func WithContext(ctx context.Context, session Context) context.Context {
	return context.WithValue(ctx, contextKey{}, session)
}

func FromContext(ctx context.Context) (Context, bool) {
	session, ok := ctx.Value(contextKey{}).(Context)
	return session, ok && session.Valid()
}

func Require(ctx context.Context) (Context, error) {
	session, ok := FromContext(ctx)
	if !ok {
		return Context{}, ErrSessionRequired
	}
	return session, nil
}

func validOwnerHash(value string) bool {
	return value == strings.TrimSpace(value) && ownerHashPattern.MatchString(value)
}
