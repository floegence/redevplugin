package plugindata

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

const (
	environmentOwnersDirName = "environment"
	userOwnersDirName        = "user"
	workspaceScopesDirName   = "scopes"
	workspaceUsersDirName    = "users"
)

func environmentScope(ctx context.Context) (sessionctx.ResourceScope, error) {
	return resourceScope(ctx, sessionctx.ScopeEnvironment)
}

func userScope(ctx context.Context) (sessionctx.ResourceScope, error) {
	return resourceScope(ctx, sessionctx.ScopeUser)
}

func requestScopes(ctx context.Context) (sessionctx.ResourceScope, sessionctx.ResourceScope, error) {
	environment, err := environmentScope(ctx)
	if err != nil {
		return sessionctx.ResourceScope{}, sessionctx.ResourceScope{}, err
	}
	user, err := userScope(ctx)
	if err != nil {
		return sessionctx.ResourceScope{}, sessionctx.ResourceScope{}, err
	}
	return environment, user, nil
}

func resourceScope(ctx context.Context, kind sessionctx.ScopeKind) (sessionctx.ResourceScope, error) {
	session, err := sessionctx.Require(ctx)
	if err != nil {
		return sessionctx.ResourceScope{}, err
	}
	return session.ResourceScope(kind)
}

func normalizedScopeKind(kind sessionctx.ScopeKind) (sessionctx.ScopeKind, error) {
	switch kind {
	case sessionctx.ScopeUser, sessionctx.ScopeEnvironment:
		return kind, nil
	default:
		return "", fmt.Errorf("%w: scope must be user or environment", ErrInvalidArgument)
	}
}

func scopedLockKey(scope sessionctx.ResourceScope, id string) string {
	return string(scope.Kind) + "\x00" + scope.OwnerEnvHash + "\x00" + scope.OwnerUserHash + "\x00" + strings.TrimSpace(id)
}

func generationCachePrefix(ownerEnvHash, generationID string) string {
	return persistentPathKey(strings.TrimSpace(ownerEnvHash), strings.TrimSpace(generationID)) + "\x00"
}

func scopedGenerationCacheKey(scope sessionctx.ResourceScope, generationID string) string {
	return generationCachePrefix(scope.OwnerEnvHash, generationID) + persistentPathKey(string(scope.Kind), scope.OwnerUserHash)
}

func scopedNamespaceCacheKey(scope sessionctx.ResourceScope, generationID, namespaceID string) string {
	return scopedGenerationCacheKey(scope, generationID) + "\x00" + strings.TrimSpace(namespaceID)
}

func persistentPathKey(parts ...string) string {
	return strings.Join(parts, "\x00")
}

func (s *FileStore) scopedWorkspacePath(scope sessionctx.ResourceScope, generationID string) string {
	return filepath.Join(s.workspacesRoot(), environmentOwnersDirName, scope.OwnerEnvHash, generationID)
}

func (s *FileStore) scopedObjectPath(scope sessionctx.ResourceScope, pluginInstanceID, objectID string) string {
	if scope.Kind == sessionctx.ScopeEnvironment {
		return filepath.Join(s.objectsRoot(), environmentOwnersDirName, scope.OwnerEnvHash, pluginInstanceID, objectID)
	}
	return filepath.Join(s.objectsRoot(), userOwnersDirName, scope.OwnerEnvHash, scope.OwnerUserHash, pluginInstanceID, objectID)
}

func workspaceScopeRoot(workspaceRoot string, scope sessionctx.ResourceScope) string {
	if scope.Kind == sessionctx.ScopeEnvironment {
		return filepath.Join(workspaceRoot, workspaceScopesDirName, environmentOwnersDirName)
	}
	return filepath.Join(workspaceRoot, workspaceScopesDirName, workspaceUsersDirName, scope.OwnerUserHash)
}

func workspaceSettingsPath(workspaceRoot string, scope sessionctx.ResourceScope) string {
	return filepath.Join(workspaceScopeRoot(workspaceRoot, scope), settingsFileName)
}

func workspaceNamespaceRoot(workspaceRoot string, scope sessionctx.ResourceScope) string {
	return filepath.Join(workspaceScopeRoot(workspaceRoot, scope), namespacesDirName)
}

func prepareResourceScopeLayout(root string) error {
	if err := removeEmptyLegacyEntries(filepath.Join(root, workspacesDirName), environmentOwnersDirName); err != nil {
		return err
	}
	objectsRoot := filepath.Join(root, objectsDirName)
	if err := removeEmptyLegacyEntries(objectsRoot, environmentOwnersDirName, userOwnersDirName); err != nil {
		return err
	}
	return rejectPluginlessObjectLayout(objectsRoot)
}

func removeEmptyLegacyEntries(root string, expected ...string) error {
	expectedNames := make(map[string]struct{}, len(expected))
	for _, name := range expected {
		expectedNames[name] = struct{}{}
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, ok := expectedNames[entry.Name()]; ok {
			if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
				return fmt.Errorf("%w: invalid owner-scoped data root", ErrUnsafeFilesystem)
			}
			continue
		}
		path := filepath.Join(root, entry.Name())
		empty, err := emptyDirectoryTree(path)
		if err != nil {
			return err
		}
		if !empty {
			return ErrOwnerScopeMigrationRequired
		}
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	return nil
}

func rejectPluginlessObjectLayout(objectsRoot string) error {
	for _, root := range []struct {
		path       string
		ownerDepth int
	}{
		{path: filepath.Join(objectsRoot, environmentOwnersDirName), ownerDepth: 1},
		{path: filepath.Join(objectsRoot, userOwnersDirName), ownerDepth: 2},
	} {
		if err := inspectObjectOwnerLayout(root.path, root.ownerDepth); err != nil {
			return err
		}
	}
	return nil
}

func inspectObjectOwnerLayout(root string, ownerDepth int) error {
	entries, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if ownerDepth > 0 {
		for _, entry := range entries {
			if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
				return fmt.Errorf("%w: invalid owner-scoped object root", ErrUnsafeFilesystem)
			}
			if err := inspectObjectOwnerLayout(filepath.Join(root, entry.Name()), ownerDepth-1); err != nil {
				return err
			}
		}
		return nil
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
			return fmt.Errorf("%w: invalid owner-scoped object root", ErrUnsafeFilesystem)
		}
		for _, legacyEntry := range []string{exportManifestName, exportPayloadName} {
			if _, err := os.Lstat(filepath.Join(root, entry.Name(), legacyEntry)); err == nil {
				return ErrOwnerScopeMigrationRequired
			} else if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func emptyDirectoryTree(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, nil
	}
	empty := true
	err = filepath.WalkDir(path, func(current string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if current != path {
			empty = false
			return fs.SkipAll
		}
		return nil
	})
	return empty, err
}
