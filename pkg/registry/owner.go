package registry

import (
	"context"
	"errors"
	"strings"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

var ErrOwnerScopeMismatch = errors.New("plugin registry owner scope mismatch")

var ErrOwnerScopeMigrationRequired = errors.New("plugin registry owner scope migration required")

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

func maintenanceCursor(parts ...string) string {
	return strings.Join(parts, "\x00")
}

func parseMaintenanceCursor(cursor string, count int) []string {
	if cursor == "" {
		return make([]string, count)
	}
	parts := strings.Split(cursor, "\x00")
	if len(parts) != count {
		return make([]string, count)
	}
	return parts
}
