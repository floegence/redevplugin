package sessionctx

import (
	"context"
	"errors"
	"strings"
)

var ErrSessionRequired = errors.New("authenticated session is required")

type Context struct {
	OwnerSessionHash     string `json:"owner_session_hash"`
	OwnerUserHash        string `json:"owner_user_hash"`
	OwnerEnvHash         string `json:"owner_env_hash"`
	SessionChannelIDHash string `json:"session_channel_id_hash"`
}

func (s Context) Valid() bool {
	return strings.TrimSpace(s.OwnerSessionHash) != "" &&
		strings.TrimSpace(s.OwnerUserHash) != "" &&
		strings.TrimSpace(s.OwnerEnvHash) != "" &&
		strings.TrimSpace(s.SessionChannelIDHash) != ""
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
