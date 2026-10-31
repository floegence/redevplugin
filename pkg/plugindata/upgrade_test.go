package plugindata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	settingsdomain "github.com/floegence/redevplugin/v3/pkg/settings"
	"github.com/floegence/redevplugin/v3/pkg/storage"
)

type upgradeTestCatalog struct {
	internalCatalog
	history []Binding
}

func TestUpgradeCannotIgnoreOutputLimitOrCancellation(t *testing.T) {
	for _, cancelConversion := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel_%v", cancelConversion), func(t *testing.T) {
			ctx, cancel := context.WithCancel(internalTestContext())
			defer cancel()
			catalog := &upgradeTestCatalog{internalCatalog: internalCatalog{objects: map[string]Object{}}}
			store, err := Open(ctx, t.TempDir(), catalog)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			shape := Shape{PublisherID: "example", PluginID: "com.example.upgrade", Namespaces: []Namespace{{ID: "notes", Kind: NamespaceKV, Scope: "user", SchemaVersion: 1, QuotaBytes: 8 << 20}}}
			dataset, err := store.InstallCommit(ctx, InstallCommitRequest{PluginInstanceID: "upgrade", Shape: shape}, func(_ context.Context, expected *Binding, next Binding, _ Shape, _ time.Time) error {
				return catalog.commitInstall(expected, next)
			})
			if err != nil {
				t.Fatal(err)
			}
			committed := false
			var escaped context.Context
			_, err = store.Upgrade(ctx, UpgradeRequest{Expected: dataset.Binding, TargetShape: shape, MaxBytes: 128 << 10}, func(ctx context.Context, w *UpgradeWorkspace) error {
				output, err := w.OutputContext(ctx, internalUserScope())
				if err != nil {
					return err
				}
				escaped = output
				if cancelConversion {
					cancel()
					return nil
				}
				_, err = store.PutKV(output, storage.KVPutRequest{PluginInstanceID: "upgrade", ResourceScope: internalUserScope(), StoreID: "notes", Key: "large", Value: []byte(strings.Repeat("x", 256<<10))})
				if !errors.Is(err, storage.ErrQuotaExceeded) {
					t.Fatalf("output limit was not enforced on write: %v", err)
				}
				// Ignoring a failed write must not turn the poisoned output into success.
				return nil
			}, func(context.Context, Binding, Binding) error { committed = true; return nil })
			if err == nil || committed || !SameBinding(*catalog.binding, dataset.Binding) {
				t.Fatalf("committed failed conversion: %v %v", committed, err)
			}
			if _, err := store.GetKV(escaped, storage.KVGetRequest{PluginInstanceID: "upgrade", ResourceScope: internalUserScope(), StoreID: "notes", Key: "large"}); err == nil {
				t.Fatal("escaped authority survived failure")
			}
		})
	}
}

func TestUpgradeAllowsSettingsTypeChangesBeforeStorageConversion(t *testing.T) {
	ctx := internalTestContext()
	catalog := &upgradeTestCatalog{internalCatalog: internalCatalog{objects: map[string]Object{}}}
	store, err := Open(ctx, t.TempDir(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	shape := Shape{PublisherID: "example", PluginID: "com.example.upgrade", Settings: settingsdomain.Schema{SchemaVersion: 1, Fields: []settingsdomain.Field{{Key: "count", Type: settingsdomain.FieldString, Scope: "user", Default: json.RawMessage(`"12"`)}}}, Namespaces: []Namespace{{ID: "notes", Kind: NamespaceKV, Scope: "user", SchemaVersion: 1, QuotaBytes: 1 << 20}}}
	dataset, err := store.InstallCommit(ctx, InstallCommitRequest{PluginInstanceID: "upgrade", Shape: shape}, func(_ context.Context, expected *Binding, next Binding, _ Shape, _ time.Time) error {
		return catalog.commitInstall(expected, next)
	})
	if err != nil {
		t.Fatal(err)
	}
	target := cloneShape(shape)
	target.Settings.SchemaVersion = 2
	target.Settings.Fields[0].Type = settingsdomain.FieldNumber
	target.Settings.Fields[0].Default = json.RawMessage(`0`)
	_, err = store.Upgrade(ctx, UpgradeRequest{Expected: dataset.Binding, TargetShape: target, MaxBytes: 8 << 20}, func(ctx context.Context, w *UpgradeWorkspace) error {
		input, err := w.ReadSettings(ctx, false, internalUserScope())
		if err != nil {
			return err
		}
		if string(input.Values["count"]) != `"12"` {
			t.Fatalf("input settings changed: %s", input.Values["count"])
		}
		output, err := w.OutputContext(ctx, internalUserScope())
		if err != nil {
			return err
		}
		if _, err := store.PutKV(output, storage.KVPutRequest{PluginInstanceID: "upgrade", ResourceScope: internalUserScope(), StoreID: "notes", Key: "body", Value: []byte("converted")}); err != nil {
			return err
		}
		return w.WriteSettings(ctx, internalUserScope(), map[string]json.RawMessage{"count": json.RawMessage(`12`)})
	}, func(_ context.Context, previous, active Binding) error {
		catalog.history = append(catalog.history, previous)
		catalog.binding = &active
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	settings, err := store.GetSettings(ctx, "upgrade", internalUserScope().Kind)
	if err != nil || string(settings.Values["count"]) != "12" {
		t.Fatalf("upgraded settings: %+v %v", settings, err)
	}
}

func (c *upgradeTestCatalog) ListAllBindingsForMaintenance(ctx context.Context, cursor string, limit int) ([]MaintenanceBinding, string, error) {
	items, next, err := c.internalCatalog.ListAllBindingsForMaintenance(ctx, cursor, limit)
	for _, binding := range c.history {
		items = append(items, MaintenanceBinding{Scope: internalEnvironmentScope(), Binding: binding})
	}
	return items, next, err
}

func TestUpgradeClonesAndKeepsBothGenerations(t *testing.T) {
	ctx := internalTestContext()
	catalog := &upgradeTestCatalog{internalCatalog: internalCatalog{objects: map[string]Object{}}}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(ctx, root, catalog)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	shape := Shape{PublisherID: "example", PluginID: "com.example.upgrade", Namespaces: []Namespace{{ID: "notes", Kind: NamespaceKV, Scope: "user", SchemaVersion: 1, QuotaBytes: 1 << 20}}}
	dataset, err := store.InstallCommit(ctx, InstallCommitRequest{PluginInstanceID: "upgrade", Shape: shape}, func(_ context.Context, expected *Binding, next Binding, _ Shape, _ time.Time) error {
		return catalog.commitInstall(expected, next)
	})
	if err != nil {
		t.Fatal(err)
	}
	request := storage.KVPutRequest{PluginInstanceID: "upgrade", ResourceScope: internalUserScope(), StoreID: "notes", Key: "body", Value: []byte("before")}
	if _, err := store.PutKV(ctx, request); err != nil {
		t.Fatal(err)
	}
	target := cloneShape(shape)
	target.Namespaces[0].SchemaVersion = 2
	var escaped context.Context
	result, err := store.Upgrade(ctx, UpgradeRequest{Expected: dataset.Binding, TargetShape: target, MaxBytes: 8 << 20}, func(ctx context.Context, workspace *UpgradeWorkspace) error {
		input, err := workspace.InputContext(ctx, internalUserScope())
		if err != nil {
			return err
		}
		output, err := workspace.OutputContext(ctx, internalUserScope())
		if err != nil {
			return err
		}
		escaped = output
		if catalog.binding.GenerationID != dataset.Binding.GenerationID {
			t.Fatal("clone became active before commit")
		}
		read := storage.KVGetRequest{PluginInstanceID: "upgrade", ResourceScope: internalUserScope(), StoreID: "notes", Key: "body"}
		value, err := store.GetKV(input, read)
		if err != nil || string(value.Value) != "before" {
			t.Fatalf("input: %q %v", value.Value, err)
		}
		request.Value = []byte("after")
		if _, err := store.PutKV(input, request); err == nil {
			t.Fatal("input allowed a write")
		}
		if _, err := store.PutKV(output, request); err != nil {
			return err
		}
		value, err = store.GetKV(input, read)
		if err != nil || string(value.Value) != "before" {
			t.Fatalf("input changed: %q %v", value.Value, err)
		}
		return nil
	}, func(_ context.Context, previous, active Binding) error {
		catalog.history = append(catalog.history, previous)
		catalog.binding = &active
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Binding.GenerationID == dataset.Binding.GenerationID || result.Binding.ShapeHash == dataset.Binding.ShapeHash {
		t.Fatal("upgrade reused source identity")
	}
	if _, err := store.PutKV(escaped, request); err == nil {
		t.Fatal("expired conversion authority remained usable")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, root, catalog)
	if err != nil {
		t.Fatal(err)
	}
	value, err := store.GetKV(ctx, storage.KVGetRequest{PluginInstanceID: "upgrade", ResourceScope: internalUserScope(), StoreID: "notes", Key: "body"})
	if err != nil || string(value.Value) != "after" {
		t.Fatalf("active after restart: %q %v", value.Value, err)
	}
	if _, err := os.Stat(store.scopedWorkspacePath(internalEnvironmentScope(), dataset.Binding.GenerationID)); err != nil {
		t.Fatalf("source garbage collected: %v", err)
	}
}

func TestUpgradeIsolatesEveryUserAndDrainsConcurrentSettings(t *testing.T) {
	ctx := internalTestContext()
	catalog := &upgradeTestCatalog{internalCatalog: internalCatalog{objects: map[string]Object{}}}
	store, err := Open(ctx, t.TempDir(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	shape := Shape{PublisherID: "example", PluginID: "com.example.upgrade", Settings: settingsdomain.Schema{SchemaVersion: 1, Fields: []settingsdomain.Field{{Key: "label", Type: settingsdomain.FieldString, Scope: "user", Default: json.RawMessage(`"default"`)}}}}
	dataset, err := store.InstallCommit(ctx, InstallCommitRequest{PluginInstanceID: "upgrade", Shape: shape}, func(_ context.Context, expected *Binding, next Binding, _ Shape, _ time.Time) error {
		return catalog.commitInstall(expected, next)
	})
	if err != nil {
		t.Fatal(err)
	}
	foreign := internalUserScope()
	foreign.OwnerUserHash = "second_user"
	session, _ := sessionctx.FromContext(ctx)
	session.OwnerUserHash = foreign.OwnerUserHash
	foreignCtx := sessionctx.WithContext(ctx, session)
	if _, err := store.PatchSettings(foreignCtx, PatchSettingsRequest{PluginInstanceID: "upgrade", Scope: sessionctx.ScopeUser, ExpectedValuesRevision: 1, Set: map[string]json.RawMessage{"label": json.RawMessage(`"second"`)}}); err != nil {
		t.Fatal(err)
	}
	_, err = store.Upgrade(ctx, UpgradeRequest{Expected: dataset.Binding, TargetShape: shape, MaxBytes: 8 << 20}, func(ctx context.Context, w *UpgradeWorkspace) error {
		if len(w.Scopes()) != 3 {
			t.Fatalf("scopes: %+v", w.Scopes())
		}
		disallowed := foreign
		disallowed.OwnerUserHash = "absent"
		if _, err := w.OutputContext(ctx, disallowed); !errors.Is(err, ErrStorageScopeMismatch) {
			t.Fatalf("unknown user: %v", err)
		}
		disallowed.OwnerEnvHash = "another_env"
		if _, err := w.InputContext(ctx, disallowed); err == nil {
			t.Fatal("cross-environment input accepted")
		}
		for _, scope := range []sessionctx.ResourceScope{internalUserScope(), foreign} {
			input, err := w.ReadSettings(ctx, false, scope)
			if err != nil {
				return err
			}
			want := `"default"`
			if scope.Matches(foreign) {
				want = `"second"`
			}
			if string(input.Values["label"]) != want {
				t.Fatalf("mixed owners: %s %s", scope.OwnerUserHash, input.Values["label"])
			}
		}
		var wg sync.WaitGroup
		errs := make(chan error, 32)
		for i := 0; i < 16; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				errs <- w.WriteSettings(ctx, foreign, map[string]json.RawMessage{"label": json.RawMessage(`"converted"`)})
			}()
			go func() { defer wg.Done(); _, err := w.ReadSettings(ctx, true, foreign); errs <- err }()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				return err
			}
		}
		return nil
	}, func(_ context.Context, previous, active Binding) error {
		catalog.history = append(catalog.history, previous)
		catalog.binding = &active
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ctx  context.Context
		want string
	}{{ctx, `"default"`}, {foreignCtx, `"converted"`}} {
		value, err := store.GetSettings(tc.ctx, "upgrade", sessionctx.ScopeUser)
		if err != nil || string(value.Values["label"]) != tc.want {
			t.Fatalf("post-upgrade owner values: %+v %v", value, err)
		}
	}
}

func TestUpgradeFailureLeavesSourceAndUnknownCommitIsNotDeleted(t *testing.T) {
	for _, failure := range []string{"converter", "quota", "commit", "unknown"} {
		t.Run(failure, func(t *testing.T) {
			ctx := internalTestContext()
			catalog := &upgradeTestCatalog{internalCatalog: internalCatalog{objects: map[string]Object{}}}
			store, err := Open(ctx, t.TempDir(), catalog)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			shape := Shape{PublisherID: "example", PluginID: "com.example.upgrade"}
			dataset, err := store.InstallCommit(ctx, InstallCommitRequest{PluginInstanceID: "upgrade", Shape: shape}, func(_ context.Context, expected *Binding, next Binding, _ Shape, _ time.Time) error {
				return catalog.commitInstall(expected, next)
			})
			if err != nil {
				t.Fatal(err)
			}
			maxBytes := int64(8 << 20)
			if failure == "quota" {
				maxBytes = 1
			}
			called := false
			_, err = store.Upgrade(ctx, UpgradeRequest{Expected: dataset.Binding, TargetShape: shape, MaxBytes: maxBytes}, func(context.Context, *UpgradeWorkspace) error {
				if failure == "converter" {
					return errors.New("conversion failed")
				}
				return nil
			}, func(_ context.Context, previous, active Binding) error {
				called = true
				if failure == "unknown" {
					catalog.history = append(catalog.history, previous)
					catalog.binding = &active
					return mutation.Unknown(errors.New("commit acknowledgement lost"))
				}
				return errors.New("commit failed")
			})
			if err == nil {
				t.Fatal("failure was accepted")
			}
			if (failure == "converter" || failure == "quota") && called {
				t.Fatal("failed conversion reached commit")
			}
			if failure != "unknown" && !SameBinding(*catalog.binding, dataset.Binding) {
				t.Fatal("failed upgrade changed active source")
			}
			for _, binding := range []Binding{dataset.Binding, *catalog.binding} {
				if _, err := os.Stat(store.scopedWorkspacePath(internalEnvironmentScope(), binding.GenerationID)); err != nil {
					t.Fatalf("live generation removed: %v", err)
				}
			}
		})
	}
}
