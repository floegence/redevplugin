package host

import (
	"context"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/capability"
)

func TestCapabilityViewRequiresExactDeclaredBindingAndLiveSandbox(t *testing.T) {
	h, receiver, source := capabilityMethodTestHost(t)
	registration, err := h.Capabilities().Resolve(*source.Contract)
	if err != nil {
		t.Fatal(err)
	}
	registration.View, err = capability.NewViewBundle("index.js", nil, map[string]capability.ViewAsset{"index.js": {ContentType: "text/javascript", Content: []byte("export function mount() {}")}})
	if err != nil {
		t.Fatal(err)
	}
	if err = h.Capabilities().Register(registration); err != nil {
		t.Fatal(err)
	}
	request, surface := openTestWebSurface(t, h, receiver.PluginInstanceID, "view_surface", surfaceMethodTestContext())
	input := ReadCapabilityViewRequest{WebSurfaceRequest: request, BindingID: "agent", Path: "index.js"}
	asset, err := h.ReadCapabilityView(context.Background(), input)
	if err != nil || string(asset.Content) != "export function mount() {}" {
		t.Fatalf("view: %+v %v", asset, err)
	}
	input.BindingID = "undeclared"
	if _, err = h.ReadCapabilityView(context.Background(), input); err == nil {
		t.Fatal("undeclared binding read")
	}
	input.BindingID = "agent"
	input.Path = "../index.js"
	if _, err = h.ReadCapabilityView(context.Background(), input); err == nil {
		t.Fatal("relative traversal accepted")
	}
	input.Path = "index.js"
	if err = h.DisposeSurface(surfaceMethodTestContext(), DisposeSurfaceRequest{SurfaceInstanceID: surface.SurfaceInstanceID, BridgeNonce: surface.BridgeNonce}); err != nil {
		t.Fatal(err)
	}
	if _, err = h.ReadCapabilityView(context.Background(), input); err == nil {
		t.Fatal("disposed sandbox read view")
	}
	// A plugin that does not declare the capability cannot load its view even
	// when the same Host has registered it for another plugin.
	other := installAndEnablePlugin(t, h, buildVersionedLifecyclePackage(t, "2.0.0", "Without capability"))
	otherRequest, _ := openTestWebSurface(t, h, other.PluginInstanceID, "without_view")
	input.WebSurfaceRequest = otherRequest
	if _, err = h.ReadCapabilityView(context.Background(), input); err == nil {
		t.Fatal("unbound plugin read view")
	}
}
