package registry

import (
	"context"
	"errors"
	"strings"

	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

var ErrOwnerScopeMismatch = errors.New("plugin registry owner scope mismatch")

func environmentOwner(ctx context.Context) (string, error) {
	scope, err := resourceOwner(ctx, sessionctx.ScopeEnvironment)
	if err != nil {
		return "", err
	}
	return scope.OwnerEnvHash, nil
}

func resourceOwner(ctx context.Context, kind sessionctx.ScopeKind) (sessionctx.ResourceScope, error) {
	session, err := sessionctx.Require(ctx)
	if err != nil {
		return sessionctx.ResourceScope{}, err
	}
	return session.ResourceScope(kind)
}

func environmentRecordKey(ownerEnvHash, pluginInstanceID string) string {
	return strings.TrimSpace(ownerEnvHash) + "\x00" + strings.TrimSpace(pluginInstanceID)
}

func scopedObjectKey(scope sessionctx.ResourceScope, pluginInstanceID, objectID string) string {
	return string(scope.Kind) + "\x00" + scope.OwnerEnvHash + "\x00" + scope.OwnerUserHash + "\x00" + strings.TrimSpace(pluginInstanceID) + "\x00" + strings.TrimSpace(objectID)
}
