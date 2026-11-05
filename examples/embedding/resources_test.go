package embedding

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/testhost"
)

// TestReferenceResourcesAndSession exercises the real platform with fake host
// policies. Production browsers use the SDK for entry, handshake and delivery.
func TestReferenceResourcesAndSession(t *testing.T) {
	ctx := context.Background()
	session := sessionctx.Context{OwnerSessionHash: "reference_session", OwnerUserHash: "reference_user", OwnerEnvHash: "reference_env", SessionChannelIDHash: "reference_channel", CanRead: true, CanWrite: true}
	h, err := testhost.Open(ctx, testhost.Options{Session: &session, ParentOrigin: "http://localhost:43210", AllowLocalPackages: true, Actions: []host.ManagementAction{
		host.ManagementActionImportLocalPackage, host.ManagementActionOpenSurface, host.ManagementActionPrepareSurface,
		host.ManagementActionDisposeSurface, host.ManagementActionMintBridgeToken, host.ManagementActionSurfaceMethods, host.ManagementActionInvokeIntent, host.ManagementActionMintStorageHandleGrant,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	ctx = h.Context(ctx)
	root := t.TempDir()
	if err := os.CopyFS(root, os.DirFS("../../testdata/generated_plugins/minimal")); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, "manifest.json")
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["api"].(map[string]any)["required_features"] = []string{"surface.resources.v1"}
	manifest["storage"] = map[string]any{"stores": []any{map[string]any{"store_id": "documents", "kind": "kv", "scope": "user", "quota_bytes": 8388608, "schema_version": 1}}}
	manifest["surfaces"].([]any)[0].(map[string]any)["web"].(map[string]any)["storage"] = []any{map[string]any{"store_id": "documents", "operations": []string{"get", "put"}}}
	empty := map[string]any{"type": "object", "additionalProperties": false}
	manifest["methods"] = []any{map[string]any{"method": "document.read", "effect": "read", "execution": "sync", "route": map[string]any{"kind": "surface", "surface_id": "minimal.view"}, "request_schema": empty, "response_schema": empty}}
	manifest["intents"] = []any{map[string]any{"intent_id": "document.read", "method": "document.read"}}
	raw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(ctx, root, &archive, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	record, err := host.ImportLocalPackageBytes(ctx, h.Host(), "reference_data", archive.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	type surface struct {
		web       host.WebSurfaceRequest
		bootstrap bridge.SurfaceBootstrap
		gateway   string
		channel   string
	}
	open := func(id string) surface {
		t.Helper()
		b, err := h.Host().OpenSurface(ctx, host.OpenSurfaceRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision, SurfaceID: "minimal.view", SurfaceInstanceID: id})
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := h.Host().PrepareSurface(ctx, host.PrepareSurfaceRequest{SurfaceInstanceID: b.SurfaceInstanceID, AssetTicket: b.AssetTicket})
		if err != nil {
			t.Fatal(err)
		}
		entry, err := url.Parse(prepared.Document.BootstrapURL)
		if err != nil {
			t.Fatal(err)
		}
		web := host.WebSurfaceRequest{Origin: prepared.Document.Origin, Token: entry.Fragment}
		entered, err := h.Host().EnterWebSurface(context.Background(), web)
		if err != nil {
			t.Fatal(err)
		}
		web.Token = entered.ResourceToken
		handshake := bridge.Handshake{PluginID: b.PluginID, SurfaceID: b.SurfaceID, SurfaceInstanceID: b.SurfaceInstanceID, ActiveFingerprint: b.ActiveFingerprint, BridgeNonce: b.BridgeNonce, AssetSessionNonce: b.AssetSessionNonce, ManagementRevision: b.ManagementRevision, RevokeEpoch: b.RevokeEpoch}
		channel := "bridge_" + id
		gateway, err := h.Host().MintBridgeToken(ctx, host.MintBridgeTokenRequest{Handshake: handshake, BridgeChannelID: channel, HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, channel)})
		if err != nil {
			t.Fatal(err)
		}
		return surface{web, b, gateway.GatewayToken, channel}
	}
	first, second := open("reference_first"), open("reference_second")
	resource := func(s surface, arguments string) (any, error) {
		return h.Host().WebResource(context.Background(), host.WebResourceRequest{WebSurfaceRequest: s.web, Resource: "storage.kv", Arguments: json.RawMessage(arguments)})
	}
	if _, err := resource(first, `{"operation":"put","store_id":"documents","key":"draft","value_base64":"aGVsbG8="}`); err != nil {
		t.Fatal(err)
	}
	value, err := resource(second, `{"operation":"get","store_id":"documents","key":"draft"}`)
	if err != nil || value.(map[string]any)["value_base64"] != "aGVsbG8=" {
		t.Fatalf("resource read: %v %v", value, err)
	}
	receiver := host.SurfaceMethodsRequest{PluginInstanceID: record.PluginInstanceID, SurfaceInstanceID: first.bootstrap.SurfaceInstanceID, BridgeChannelID: first.channel, GatewayToken: first.gateway, Operation: "register", Methods: []string{"document.read"}}
	registered, err := h.Host().SurfaceMethods(ctx, receiver)
	if err != nil {
		t.Fatal(err)
	}
	receiver.ReceiverID, receiver.Methods, receiver.Operation = registered.ReceiverID, nil, "claim"
	call := make(chan error, 1)
	go func() {
		_, err := h.Host().InvokeIntent(ctx, host.InvokeIntentRequest{PluginInstanceID: record.PluginInstanceID, SurfaceInstanceID: first.bootstrap.SurfaceInstanceID, IntentID: "document.read"})
		call <- err
	}()
	claimed, err := h.Host().SurfaceMethods(ctx, receiver)
	if err != nil || claimed.Invocation == nil {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	receiver.Operation, receiver.InvocationID, receiver.Data = "complete", claimed.Invocation.InvocationID, map[string]any{}
	if _, err := h.Host().SurfaceMethods(ctx, receiver); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-call:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("intent did not complete")
	}
	if err := h.Host().DisposeSurface(ctx, host.DisposeSurfaceRequest{SurfaceInstanceID: first.bootstrap.SurfaceInstanceID, BridgeNonce: first.bootstrap.BridgeNonce}); err != nil {
		t.Fatal(err)
	}
	if _, err := resource(first, `{"operation":"get","store_id":"documents","key":"draft"}`); err == nil {
		t.Fatal("closed surface retained access")
	}
	if _, err := resource(second, `{"operation":"get","store_id":"documents","key":"draft"}`); err != nil {
		t.Fatalf("sibling lost access: %v", err)
	}
	closed, err := h.Host().CloseAuthenticatedSessionScope(context.Background(), host.CloseAuthenticatedSessionScopeRequest{Session: session})
	if err != nil || closed.Status != host.SessionScopeTeardownComplete {
		t.Fatalf("session teardown: %+v %v", closed, err)
	}
	if _, err := resource(second, `{"operation":"get","store_id":"documents","key":"draft"}`); err == nil {
		t.Fatal("revoked session retained access")
	}
}
