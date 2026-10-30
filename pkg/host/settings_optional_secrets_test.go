package host

import (
	"errors"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/secrets"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

func TestOrdinarySettingsDoNotRequireSecrets(t *testing.T) {
	for _, withUnavailableVault := range []bool{false, true} {
		name := "core only"
		if withUnavailableVault {
			name = "unavailable unrelated vault"
		}
		t.Run(name, func(t *testing.T) {
			config := modularTestConfig(t)
			if withUnavailableVault {
				config.Secrets = &SecretsModule{Store: &failingSecretListStore{
					SecretStoreAdapter: secrets.NewMemoryStore(), err: errors.New("unrelated vault unavailable"),
				}}
			}
			h, err := Open(hostTestContext(), config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = h.Close() })
			installed := importCurrentLifecyclePackage(t, h, currentSettingsManifestJSON())
			request := GetSettingsRequest{PluginInstanceID: installed.PluginInstanceID, Scope: sessionctx.ScopeUser}
			before, err := h.GetPluginSettings(hostTestContext(), request)
			if err != nil {
				t.Fatal(err)
			}
			if before.Values["show_stopped"] != true || before.SecretMetadata == nil || len(before.SecretMetadata) != 0 {
				t.Fatalf("initial settings = %#v, want defaults and an empty metadata array", before)
			}
			after, err := h.PatchPluginSettings(hostTestContext(), PatchSettingsRequest{
				PluginInstanceID: installed.PluginInstanceID, Scope: request.Scope,
				ExpectedValuesRevision: before.ValuesRevision, Set: map[string]any{"show_stopped": false},
			})
			if err != nil {
				t.Fatal(err)
			}
			if after.Values["show_stopped"] != false || after.ValuesRevision <= before.ValuesRevision || after.SecretMetadata == nil || len(after.SecretMetadata) != 0 {
				t.Fatalf("patched settings = %#v, want persisted values and an empty metadata array", after)
			}
			reopened, err := h.GetPluginSettings(hostTestContext(), request)
			if err != nil || reopened.Values["show_stopped"] != false || reopened.ValuesRevision != after.ValuesRevision {
				t.Fatalf("read after patch = %#v, err=%v", reopened, err)
			}
		})
	}
}

func TestSettingsOnlyReadSecretsForTheRequestedScope(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	manifestJSON := strings.Replace(currentSettingsManifestJSON(), `"fields": [`, `"fields": [{"key": "environment_token", "type": "secret", "scope": "environment", "label": "Environment token", "secret_ref": "environment_token"},`, 1)
	installed := importCurrentLifecyclePackage(t, h, manifestJSON)
	h.adapters.Secrets = &failingSecretListStore{SecretStoreAdapter: h.adapters.Secrets, err: errors.New("environment vault unavailable")}
	result, err := h.GetPluginSettings(hostTestContext(), GetSettingsRequest{PluginInstanceID: installed.PluginInstanceID, Scope: sessionctx.ScopeUser})
	if err != nil || result.SecretMetadata == nil || len(result.SecretMetadata) != 0 {
		t.Fatalf("user settings = %#v, err=%v; want no environment vault access", result, err)
	}
}

func TestSettingsSecretPreflightDoesNotCommitValues(t *testing.T) {
	for _, missingModule := range []bool{true, false} {
		name := "missing module"
		if !missingModule {
			name = "unavailable vault"
		}
		t.Run(name, func(t *testing.T) {
			h, _, _ := newTestHost(t, true, true)
			manifestJSON := strings.Replace(currentSettingsManifestJSON(), `"fields": [`, `"fields": [{"key": "api_token", "type": "secret", "scope": "user", "label": "API token", "secret_ref": "api_token"},`, 1)
			installed := importCurrentLifecyclePackage(t, h, manifestJSON)
			before, err := h.adapters.PluginData.GetSettings(hostTestContext(), installed.PluginInstanceID, sessionctx.ScopeUser)
			if err != nil {
				t.Fatal(err)
			}
			if missingModule {
				disableModuleFeatures(h, FeatureSecrets)
			} else {
				h.adapters.Secrets = &failingSecretListStore{SecretStoreAdapter: h.adapters.Secrets, err: errors.New("vault unavailable")}
			}
			_, err = h.GetPluginSettings(hostTestContext(), GetSettingsRequest{PluginInstanceID: installed.PluginInstanceID, Scope: sessionctx.ScopeUser})
			if err == nil {
				t.Fatal("reading secret settings should report the unavailable authority")
			}
			if missingModule {
				assertMissingFeatures(t, err, FeatureSecrets)
			}
			_, err = h.PatchPluginSettings(hostTestContext(), PatchSettingsRequest{
				PluginInstanceID: installed.PluginInstanceID, Scope: sessionctx.ScopeUser,
				ExpectedValuesRevision: before.Revision, Set: map[string]any{"show_stopped": false},
			})
			if err == nil || mutation.ForError(err) == mutation.OutcomeUnknown {
				t.Fatalf("patch error = %v; want a rejected preflight, not an unknown write", err)
			}
			if missingModule {
				assertMissingFeatures(t, err, FeatureSecrets)
			}
			after, err := h.adapters.PluginData.GetSettings(hostTestContext(), installed.PluginInstanceID, sessionctx.ScopeUser)
			if err != nil || after.Revision != before.Revision || string(after.Values["show_stopped"]) != "true" {
				t.Fatalf("settings changed after preflight failure: %#v, err=%v", after, err)
			}
		})
	}
}
