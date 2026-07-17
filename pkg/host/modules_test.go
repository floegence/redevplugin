package host

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/redevplugin/pkg/secrets"
)

func TestOpenConfigRequiresCompleteCoreAdapters(t *testing.T) {
	_, err := Open(context.Background(), Config{Core: CoreAdapters{}})
	if err == nil {
		t.Fatal("Open() accepted an incomplete core adapter set")
	}
	if errors.Is(err, ErrFeatureNotConfigured) {
		t.Fatalf("core validation returned optional feature error: %v", err)
	}
}

func TestOpenConfigRejectsIncompleteDeclaredModules(t *testing.T) {
	config := modularTestConfig(t)
	config.Runtime = &RuntimeModule{}
	_, err := Open(context.Background(), config)
	if err == nil {
		t.Fatal("Open() accepted incomplete runtime module")
	}
	if !errors.Is(err, ErrRuntimeModuleRequired) {
		t.Fatalf("Open() error = %v, want ErrRuntimeModuleRequired", err)
	}
}

func TestFeaturesReturnsClosedConfiguredSet(t *testing.T) {
	config := modularTestConfig(t)
	config.Runtime = &RuntimeModule{Manager: config.RuntimeManager}
	config.SecretsModule = &SecretsModule{Store: secrets.NewMemoryStore()}
	h, err := Open(context.Background(), config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	want := []string{"runtime", "secrets"}
	got := h.Features()
	if len(got) != len(want) {
		t.Fatalf("Features() = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Features() = %#v, want %#v", got, want)
		}
	}
}

func modularTestConfig(t *testing.T) Config {
	legacy, _, _ := newTestHost(t, true, true)
	adapters := legacy.adapters
	return Config{Core: CoreAdapters{
		Policy:              adapters.Policy,
		Registry:            adapters.Registry,
		Audit:               adapters.Audit,
		Diagnostics:         adapters.Diagnostics,
		SurfaceCatalog:      adapters.SurfaceCatalog,
		SurfaceTokens:       adapters.SurfaceTokens,
		PluginData:          adapters.PluginData,
		Assets:              adapters.Assets,
		InstallStages:       adapters.InstallStages,
		Operations:          adapters.Operations,
		ConfirmationIntents: adapters.ConfirmationIntents,
		Streams:             adapters.Streams,
	}, RuntimeManager: adapters.RuntimeManager}
}
