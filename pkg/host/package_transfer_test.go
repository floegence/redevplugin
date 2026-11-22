package host

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/externalsource"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

func TestFileBackedPluginDownloadsOnlyAfterPreviewAndInstalls(t *testing.T) {
	seed := buildFixturePackage(t)
	base, err := zip.NewReader(bytes.NewReader(seed), int64(len(seed)))
	if err != nil {
		t.Fatal(err)
	}
	archive, err := os.CreateTemp(t.TempDir(), "archive-*")
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	writer := zip.NewWriter(archive)
	for _, part := range base.File {
		if err := writer.Copy(part); err != nil {
			t.Fatal(err)
		}
	}
	out, err := writer.CreateHeader(&zip.FileHeader{Name: "ui/assets/offline.dat", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	chunks := 33
	if os.Getenv("REDEVPLUGIN_TEST_LARGE_TRANSFER") == "1" {
		chunks = 3072
	}
	chunk := make([]byte, 1<<20)
	for range chunks {
		if _, err := out.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := archive.Stat()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.New()
	if _, err = archive.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err = archive.WriteTo(digest); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); http.ServeFile(w, r, archive.Name()) }))
	defer server.Close()
	config := modularTestConfig(t)
	assets, err := pluginpkg.NewFileAssetStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer assets.Close()
	config.Core.Assets = assets
	config.ExternalPackage = &ExternalPackageModule{Transport: server.Client().Transport}
	ctx := hostTestContext()
	host, err := Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	source := ExternalPackageSource{Kind: "package_url", URL: server.URL + "/package.redevplugin"}
	if _, err := host.PreviewExternalPackage(ctx, PreviewPackageRequest{Source: &source}); err != nil || requests.Load() != 0 {
		t.Fatalf("preview: calls=%d err=%v", requests.Load(), err)
	}
	inspection, err := host.InspectExternalPackage(ctx, InspectExternalPackageRequest{Intent: ExternalPackageIntent{Action: "install"}, Source: source, ExpectedArchiveSHA256: hex.EncodeToString(digest.Sum(nil))})
	if err != nil {
		t.Fatal(err)
	}
	if inventory, err := host.ListPlugins(ctx); err != nil || len(inventory) != 0 {
		t.Fatalf("inspection installed a plugin: %v %v", inventory, err)
	}
	installed, err := host.installInspectedPackage(ctx, installInspectedPackageRequest{InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256})
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := host.ListPlugins(ctx)
	if err != nil || len(inventory) != 1 || installed.Plugin == nil || inventory[0].PluginInstanceID != installed.Plugin.PluginInstanceID || inventory[0].EnableState != registry.EnableEnabled || requests.Load() != 1 {
		t.Fatalf("install calls=%d records=%d err=%v", requests.Load(), len(inventory), err)
	}
	if err := assets.VerifyAsset(ctx, inventory[0].PackageHash, "ui/assets/offline.dat"); err != nil {
		t.Fatal(err)
	}
	t.Logf("archive=%d asset=%d fetches=%d installed=%d", info.Size(), int64(chunks)<<20, requests.Load(), len(inventory))
}

type observedPackageFetcher struct {
	started chan struct{}
}

func TestPackageArchiveExpectations(t *testing.T) {
	host, _, _ := newTestHostWithOptions(t, testHostOptions{})
	stage := &externalPackageTestStage{}
	configureExternalPackageTestModule(host, stage)
	request := InspectExternalPackageRequest{Intent: ExternalPackageIntent{Action: "install"}, Source: ExternalPackageSource{Kind: "package_url", URL: "https://packages.example.test/plugin"}, ExpectedArchiveSHA256: "invalid"}
	if _, err := host.InspectExternalPackage(hostTestContext(), request); !errors.Is(err, ErrExternalPackageRequestInvalid) || stage.removedCount() != 0 {
		t.Fatalf("invalid digest: %v", err)
	}
	request.ExpectedArchiveSHA256 = strings.Repeat("0", 64)
	if _, err := host.InspectExternalPackage(hostTestContext(), request); !errors.Is(err, ErrExternalPackageConfirmation) || stage.removedCount() != 1 {
		t.Fatalf("changed archive: %v", err)
	}
}

func (fetcher observedPackageFetcher) FetchPackage(ctx context.Context, req externalsource.FetchRequest) (externalsource.FetchResult, error) {
	req.Progress(500, 1000)
	close(fetcher.started)
	<-ctx.Done()
	return externalsource.FetchResult{}, ctx.Err()
}

func TestPackageTransferScopeAndCancel(t *testing.T) {
	host, _, _ := newTestHostWithOptions(t, testHostOptions{})
	configureExternalPackageTestModule(host, &externalPackageTestStage{})
	fetcher := observedPackageFetcher{started: make(chan struct{})}
	host.adapters.ExternalPackageFetcher = fetcher
	ctx := hostTestContext()
	other := hostTestContextWith("other_session", "user_hash", "env_hash", "other_channel")
	request := PackageTransferRequest{TransferID: "0123456789abcdef"}
	source := ExternalPackageSource{Kind: "package_url", URL: "https://packages.example.test/plugin"}
	preview, err := host.PreviewExternalPackage(ctx, PreviewPackageRequest{Source: &source})
	if err != nil || preview.Kind != source.Kind || preview.Size != 0 {
		t.Fatalf("preview=%+v err=%v", preview, err)
	}
	result := make(chan error, 1)
	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		_, err := host.InspectExternalPackage(requestCtx, InspectExternalPackageRequest{Intent: ExternalPackageIntent{Action: "install"}, Source: source, TransferID: request.TransferID})
		result <- err
	}()
	select {
	case <-fetcher.started:
	case err := <-result:
		t.Fatalf("transfer failed to start: %v", err)
	}
	if state, err := host.CancelPackageTransfer(other, request); err != nil || state.Stage != "inactive" {
		t.Fatalf("other session: %+v %v", state, err)
	}
	if state, err := host.PackageTransferProgress(ctx, request); err != nil || state != (PackageTransferProgress{Stage: "downloading", ReceivedBytes: 500, TotalBytes: 1000}) {
		t.Fatalf("active state: %+v %v", state, err)
	}
	if _, err := host.CancelPackageTransfer(ctx, request); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	if state, err := host.PackageTransferProgress(ctx, request); err != nil || state.Stage != "inactive" {
		t.Fatalf("finished state: %+v %v", state, err)
	}
}
