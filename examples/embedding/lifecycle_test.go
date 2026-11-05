package embedding

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/testhost"
)

// Example_referenceLifecycle uses the deny-by-default test adapters. A product
// replaces them with its own session, authorization, origin, and audit adapters.
func Example_referenceLifecycle() {
	root, err := os.MkdirTemp("", "redevplugin-reference-host-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(root)
	options := testhost.Options{
		StateRoot: filepath.Join(root, "state"), ParentOrigin: "http://localhost:43210",
		AllowLocalPackages: true,
		Actions: []host.ManagementAction{host.ManagementActionImportLocalPackage, host.ManagementActionListPlugins,
			host.ManagementActionOpenSurface, host.ManagementActionPrepareSurface, host.ManagementActionDisposeSurface},
	}
	platform, err := testhost.Open(context.Background(), options)
	if err != nil {
		panic(err)
	}
	ctx := platform.Context(context.Background())
	var archive bytes.Buffer
	if _, err = pluginpkg.BuildFromDir(ctx, "../../testdata/generated_plugins/minimal", &archive, pluginpkg.DefaultReadLimits()); err != nil {
		panic(err)
	}
	record, err := host.ImportLocalPackageBytes(ctx, platform.Host(), "reference_plugin", archive.Bytes())
	if err != nil {
		panic(err)
	}
	request, err := platform.NewRequest(ctx, http.MethodPost, "/_redevplugin/api/plugins/catalog/query", strings.NewReader("{}"))
	if err != nil {
		panic(err)
	}
	response := httptest.NewRecorder()
	platform.Handler(nil).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		panic(response.Body.String())
	}
	open := func(id string) {
		surface, failure := platform.Host().OpenSurface(ctx, host.OpenSurfaceRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision, SurfaceID: "minimal.view", SurfaceInstanceID: id})
		if failure != nil {
			panic(failure)
		}
		if _, failure = platform.Host().PrepareSurface(ctx, host.PrepareSurfaceRequest{SurfaceInstanceID: surface.SurfaceInstanceID, AssetTicket: surface.AssetTicket}); failure != nil {
			panic(failure)
		}
		if failure = platform.Host().DisposeSurface(ctx, host.DisposeSurfaceRequest{SurfaceInstanceID: surface.SurfaceInstanceID, BridgeNonce: surface.BridgeNonce}); failure != nil {
			panic(failure)
		}
	}
	open("reference_first")
	session := platform.Session()
	if err = platform.Close(); err != nil {
		panic(err)
	}
	options.Session = &session
	platform, err = testhost.Open(context.Background(), options)
	if err != nil {
		panic(err)
	}
	defer platform.Close()
	ctx = platform.Context(context.Background())
	records, err := platform.Host().ListPlugins(ctx)
	if err != nil || len(records) != 1 {
		panic("installed inventory unavailable after restart")
	}
	record = records[0]
	open("reference_reopened")
	fmt.Println("authenticated catalog:", response.Code)
	fmt.Println("installed after restart:", len(records))
	fmt.Println("independent surfaces opened and closed")
	// Output:
	// authenticated catalog: 200
	// installed after restart: 1
	// independent surfaces opened and closed
}
