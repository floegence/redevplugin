package externalsource

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
)

func TestMultiGiBHTTPSPackage(t *testing.T) {
	if os.Getenv("REDEVPLUGIN_TEST_LARGE_TRANSFER") != "1" {
		t.Skip("requires temporary disk space for a multi-GiB transfer")
	}
	const size int64 = 3 << 30
	seed := buildMinimalPackage(t)
	base, err := zip.NewReader(bytes.NewReader(seed), int64(len(seed)))
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.(http.Flusher).Flush()
		archive := zip.NewWriter(w)
		for _, file := range base.File {
			if err := archive.Copy(file); err != nil {
				t.Error(err)
				return
			}
		}
		body, err := archive.CreateHeader(&zip.FileHeader{Name: "ui/assets/offline.dat", Method: zip.Store})
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := io.CopyN(body, zeroPackageStream{}, size); err != nil {
			t.Error(err)
			return
		}
		if err := archive.Close(); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	stage, err := NewStageStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	fetcher, err := NewFetcher(FetcherOptions{Stage: stage, Transport: server.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	defer fetcher.CloseIdleConnections()
	ctx := context.Background()
	var received int64
	result, err := fetcher.FetchPackage(ctx, FetchRequest{URL: server.URL + "/plugin", Progress: func(done, total int64) {
		if total != 0 || done < received {
			t.Fatal("invalid chunked transfer progress")
		}
		received = done
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stage.Remove(result.Artifact); err != nil {
			t.Error(err)
		}
	}()
	if received <= size || result.Artifact.Size != received || requests.Load() != 1 {
		t.Fatalf("received=%d staged=%d requests=%d", received, result.Artifact.Size, requests.Load())
	}
	pkg, err := stage.VerifyFileBackedPackage(ctx, result.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	assets, err := pluginpkg.NewFileAssetStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer assets.Close()
	if err := assets.PutOwnedPackage(ctx, &pkg); err != nil {
		t.Fatal(err)
	}
	if err := assets.VerifyAsset(ctx, pkg.PackageHash, "ui/assets/offline.dat"); err != nil {
		t.Fatal(err)
	}
	t.Logf("requests=%d received=%d verified_asset_bytes=%d", requests.Load(), received, size)
}

type zeroPackageStream struct{}

func TestDownloadDeadlineTracksActivity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, touch, stop := downloadIdleContext(context.Background(), time.Minute)
		defer stop()
		for range 20 {
			time.Sleep(45 * time.Second)
			touch()
			if err := ctx.Err(); err != nil {
				t.Fatalf("active transfer timed out: %v", err)
			}
		}
		time.Sleep(time.Minute + 1)
		synctest.Wait()
		if !errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			t.Fatal("idle transfer was not canceled")
		}
	})
}

func TestDownloadChecksFreeSpaceBeforeAndDuringTransfer(t *testing.T) {
	for _, known := range []bool{true, false} {
		fetcher, directory := newTestFetcher(t, staticResolver{"example.com": {netip.MustParseAddr("1.1.1.1")}})
		checks := 0
		fetcher.stage.freeBytes = func(*os.Root) (int64, error) {
			checks++
			if !known && checks <= 2 {
				return 1 << 30, nil
			}
			return stageSpaceReserve, nil
		}
		fetcher.roundTrip = func(context.Context, PackageURL, []netip.Addr, http.Header) (*http.Response, error) {
			var body io.Reader = zeroPackageStream{}
			length := int64(-1)
			if known {
				body = panicReader{}
				length = 7 << 30
			}
			return &http.Response{StatusCode: http.StatusOK, ContentLength: length, Header: make(http.Header), Body: io.NopCloser(body)}, nil
		}
		_, err := fetcher.FetchPackage(context.Background(), FetchRequest{URL: "https://example.com/plugin"})
		if CodeOf(err) != ErrorQuotaExceeded {
			t.Fatalf("known=%t err=%v", known, err)
		}
		if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
			t.Fatalf("partial stage: %v, %v", entries, err)
		}
	}
}

func (zeroPackageStream) Read(buffer []byte) (int, error) {
	clear(buffer)
	return len(buffer), nil
}

func TestPackageDownloadStreamsBeyondLegacyLimit(t *testing.T) {
	const size = MaxArtifactBytes + 1
	fetcher, _ := newTestFetcher(t, staticResolver{"example.com": {netip.MustParseAddr("1.1.1.1")}})
	fetcher.roundTrip = func(context.Context, PackageURL, []netip.Addr, http.Header) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, ContentLength: size, Header: make(http.Header), Body: io.NopCloser(io.LimitReader(zeroPackageStream{}, size))}, nil
	}
	var received int64
	result, err := fetcher.FetchPackage(context.Background(), FetchRequest{URL: "https://example.com/plugin", Progress: func(completed, total int64) {
		received = completed
	}})
	if err != nil || result.Artifact.Size != size || received != size {
		t.Fatalf("artifact=%d received=%d err=%v", result.Artifact.Size, received, err)
	}
	if err := fetcher.stage.Remove(result.Artifact); err != nil {
		t.Fatal(err)
	}
}

func TestDownloadCancellationRemovesPartialFile(t *testing.T) {
	fetcher, directory := newTestFetcher(t, staticResolver{"example.com": {netip.MustParseAddr("1.1.1.1")}})
	fetcher.roundTrip = func(context.Context, PackageURL, []netip.Addr, http.Header) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, ContentLength: -1, Header: make(http.Header), Body: io.NopCloser(zeroPackageStream{})}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := fetcher.FetchPackage(ctx, FetchRequest{URL: "https://example.com/plugin", Progress: func(completed, total int64) { cancel() }})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("partial stage: %v, %v", entries, err)
	}
}

func TestPreviewGitHubPackageNeverFetchesAsset(t *testing.T) {
	const size int64 = 5 << 30
	fetcher, directory := newTestFetcher(t, nil)
	fetcher.roundTrip = func(context.Context, PackageURL, []netip.Addr, http.Header) (*http.Response, error) {
		t.Fatal("preview requested an asset")
		return nil, nil
	}
	client := &fakeGitHubClient{release: GitHubRelease{RepositoryID: 1, ReleaseID: 2, ResolvedCommitSHA: strings.Repeat("a", 40), Tag: "plugin-v1.0.0", Assets: []GitHubReleaseAsset{{AssetID: 3, Name: "plugin.redevplugin", DownloadURL: "https://example.com/plugin?token=secret", Size: size}}}}
	resolver, err := NewGitHubReleaseResolver(client, fetcher)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := resolver.PreviewPackage(context.Background(), GitHubRepositorySource{RepositoryURL: "https://github.com/example/plugin", Tag: client.release.Tag})
	if err != nil || preview.DeclaredSize != size || preview.AssetID != 3 || preview.Version != "1.0.0" || client.byTagCalls != 1 {
		t.Fatalf("preview=%+v calls=%d err=%v", preview, client.byTagCalls, err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("preview staged data: %v, %v", entries, err)
	}
}

func TestFetchPackageReportsReceivedBytes(t *testing.T) {
	for _, test := range []struct {
		name   string
		length int64
	}{{"known", 5}, {"unknown", -1}} {
		t.Run(test.name, func(t *testing.T) {
			fetcher, _ := newTestFetcher(t, staticResolver{"example.com": {netip.MustParseAddr("1.1.1.1")}})
			fetcher.roundTrip = func(context.Context, PackageURL, []netip.Addr, http.Header) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, ContentLength: test.length, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("bytes"))}, nil
			}
			var received int64
			result, err := fetcher.FetchPackage(context.Background(), FetchRequest{URL: "https://example.com/plugin", Progress: func(completed, total int64) {
				if total != max(test.length, 0) || completed < received || completed > 5 {
					t.Fatalf("invalid progress: %d of %d", completed, total)
				}
				received = completed
			}})
			if err != nil || received != 5 {
				t.Fatalf("received=%d err=%v", received, err)
			}
			if err = fetcher.stage.Remove(result.Artifact); err != nil {
				t.Fatal(err)
			}
		})
	}
}
