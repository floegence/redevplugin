package remoterelease

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/externalsource"
	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/releasecontract"
)

type memoryFetcher struct {
	values   map[string][]byte
	requests []externalsource.ArtifactFetchRequest
	failures []error
	block    bool
}

func (fetcher *memoryFetcher) FetchArtifact(ctx context.Context, request externalsource.ArtifactFetchRequest) (externalsource.ArtifactFetchResult, error) {
	fetcher.requests = append(fetcher.requests, request)
	if fetcher.block {
		<-ctx.Done()
		return externalsource.ArtifactFetchResult{}, ctx.Err()
	}
	if len(fetcher.failures) > 0 {
		err := fetcher.failures[0]
		fetcher.failures = fetcher.failures[1:]
		if err != nil {
			return externalsource.ArtifactFetchResult{}, err
		}
	}
	value := fetcher.values[request.URL]
	if request.Progress != nil {
		request.Progress(int64(len(value)), int64(len(value)))
	}
	return externalsource.ArtifactFetchResult{Bytes: append([]byte(nil), value...), Source: request.URL, Final: request.URL}, nil
}

func TestAssetSetBoundsUnresponsiveFetcher(t *testing.T) {
	value := []byte("document")
	url := "https://artifacts.example.test/document.json"
	fetcher := &memoryFetcher{values: map[string][]byte{url: value}, block: true}
	set, err := NewAssetSet(AssetSetOptions{
		SourceID: "example", Channel: "stable", AllowedHosts: []string{"artifacts.example.test"}, Fetcher: fetcher,
		FetchTimeout: 10 * time.Millisecond,
		Assets:       []Asset{asset("sources/example/root/current.json", url, value)},
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, _, err = set.fetch(context.Background(), "sources/example/root/current.json", "release_document", 1024, []string{"artifacts.example.test"}, "", nil)
	if time.Since(started) > time.Second {
		t.Fatalf("unresponsive fetch took too long: %s", time.Since(started))
	}
	var releaseErr *Error
	if !errors.As(err, &releaseErr) || !errors.Is(err, context.DeadlineExceeded) || releaseErr.Attempts != 1 || !releaseErr.Retryable {
		t.Fatalf("bounded fetch error = %#v, want retryable context deadline after one attempt", err)
	}
}

func TestAssetSetRetriesOnlyTransientContentAddressedFetches(t *testing.T) {
	value := []byte("document")
	url := "https://artifacts.example.test/document.json"
	fetcher := &memoryFetcher{
		values: map[string][]byte{url: value},
		failures: []error{
			externalsource.NewHTTPStatusError("fetch", url, http.StatusServiceUnavailable, 3*time.Second),
			errors.New("unused placeholder"),
		},
	}
	set, err := NewAssetSet(AssetSetOptions{SourceID: "example", Channel: "stable", AllowedHosts: []string{"artifacts.example.test"}, Fetcher: fetcher, Assets: []Asset{
		asset("sources/example/root/current.json", url, value),
	}})
	if err != nil {
		t.Fatal(err)
	}
	var delays []time.Duration
	set.sleep = func(_ context.Context, delay time.Duration) error { delays = append(delays, delay); return nil }
	set.jitter = func(time.Duration) time.Duration { return 0 }
	// Replace the second placeholder with success after the first retry.
	fetcher.failures = fetcher.failures[:1]
	got, _, err := set.fetch(context.Background(), "sources/example/root/current.json", "release_document", 1024, []string{"artifacts.example.test"}, "", nil)
	if err != nil || string(got) != string(value) || len(fetcher.requests) != 2 || len(delays) != 1 || delays[0] != 3*time.Second {
		t.Fatalf("retry result=%q requests=%d delays=%v err=%v", got, len(fetcher.requests), delays, err)
	}

	permanent := &memoryFetcher{values: map[string][]byte{url: value}, failures: []error{
		externalsource.NewHTTPStatusError("fetch", url, http.StatusNotFound, 0),
	}}
	set, err = NewAssetSet(AssetSetOptions{SourceID: "example", Channel: "stable", AllowedHosts: []string{"artifacts.example.test"}, Fetcher: permanent, Assets: []Asset{
		asset("sources/example/root/current.json", url, value),
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = set.fetch(context.Background(), "sources/example/root/current.json", "release_document", 1024, []string{"artifacts.example.test"}, "", nil)
	var releaseErr *Error
	if !errors.As(err, &releaseErr) || releaseErr.Retryable || releaseErr.Attempts != 1 || len(permanent.requests) != 1 {
		t.Fatalf("permanent error=%#v requests=%d", err, len(permanent.requests))
	}
}

func TestAssetSetCachesAndRevalidatesImmutableAsset(t *testing.T) {
	value := []byte("immutable release evidence")
	rawURL := "https://artifacts.example.test/evidence.json"
	assetValue := asset("sources/example/root/evidence.json", rawURL, value)
	fetcher := &memoryFetcher{values: map[string][]byte{rawURL: value}}
	set, err := NewAssetSet(AssetSetOptions{
		SourceID: "example", Channel: "stable", AllowedHosts: []string{"artifacts.example.test"},
		Fetcher: fetcher, Assets: []Asset{assetValue},
	})
	if err != nil {
		t.Fatal(err)
	}

	first, _, err := set.fetch(context.Background(), assetValue.Locator, "release_document", 1024, []string{"artifacts.example.test"}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	first[0] ^= 0xff
	var observed []host.ReleaseArtifactProgress
	second, _, err := set.fetch(context.Background(), assetValue.Locator, "release_document", 1024, []string{"artifacts.example.test"}, "", func(progress host.ReleaseArtifactProgress) {
		observed = append(observed, progress)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second, value) || len(fetcher.requests) != 1 {
		t.Fatalf("cached bytes=%q requests=%d", second, len(fetcher.requests))
	}
	if len(observed) != 1 || !observed[0].CacheHit || observed[0].Completed != int64(len(value)) || observed[0].Total != int64(len(value)) {
		t.Fatalf("cache observation = %#v", observed)
	}
	set.cacheMu.Lock()
	set.cache[assetValue.SHA256][0] ^= 0xff
	set.cacheMu.Unlock()
	recovered, _, err := set.fetch(context.Background(), assetValue.Locator, "release_document", 1024, []string{"artifacts.example.test"}, "", nil)
	if err != nil || !bytes.Equal(recovered, value) || len(fetcher.requests) != 2 {
		t.Fatalf("corrupt cache recovery bytes=%q requests=%d error=%v", recovered, len(fetcher.requests), err)
	}
}

func TestAssetSetSingleFlightsConcurrentImmutableAssetFetches(t *testing.T) {
	value := []byte("shared immutable checkpoint")
	rawURL := "https://artifacts.example.test/checkpoint.json"
	assetValue := asset("sources/example/signing-ledger/checkpoint.json", rawURL, value)
	fetcher := &blockingFetcher{value: value, started: make(chan struct{}, 5), release: make(chan struct{})}
	set, err := NewAssetSet(AssetSetOptions{
		SourceID: "example", Channel: "stable", AllowedHosts: []string{"artifacts.example.test"},
		Fetcher: fetcher, Assets: []Asset{assetValue},
	})
	if err != nil {
		t.Fatal(err)
	}

	const callers = 5
	start := make(chan struct{})
	done := make(chan error, callers)
	for range callers {
		go func() {
			<-start
			got, _, fetchErr := set.fetch(context.Background(), assetValue.Locator, "signing_ledger", 1024, []string{"artifacts.example.test"}, "", nil)
			if fetchErr == nil && !bytes.Equal(got, value) {
				fetchErr = errors.New("single-flight caller received wrong bytes")
			}
			done <- fetchErr
		}()
	}
	close(start)
	select {
	case <-fetcher.started:
	case <-time.After(time.Second):
		t.Fatal("immutable asset fetch did not start")
	}
	select {
	case <-fetcher.started:
		close(fetcher.release)
		for range callers {
			<-done
		}
		t.Fatalf("underlying fetch calls reached %d before completion, want one single-flight owner", fetcher.calls.Load())
	case <-time.After(250 * time.Millisecond):
	}
	close(fetcher.release)
	for range callers {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if fetcher.calls.Load() != 1 {
		t.Fatalf("underlying fetch calls = %d, want 1", fetcher.calls.Load())
	}
}

func TestAssetSetSingleFlightWaiterCancellationDoesNotCancelOwner(t *testing.T) {
	value := []byte("shared immutable checkpoint")
	rawURL := "https://artifacts.example.test/checkpoint.json"
	assetValue := asset("sources/example/signing-ledger/checkpoint.json", rawURL, value)
	fetcher := &blockingFetcher{value: value, started: make(chan struct{}, 2), release: make(chan struct{})}
	set, err := NewAssetSet(AssetSetOptions{
		SourceID: "example", Channel: "stable", AllowedHosts: []string{"artifacts.example.test"},
		Fetcher: fetcher, Assets: []Asset{assetValue},
	})
	if err != nil {
		t.Fatal(err)
	}
	ownerDone := make(chan error, 1)
	go func() {
		_, _, fetchErr := set.fetch(context.Background(), assetValue.Locator, "signing_ledger", 1024, []string{"artifacts.example.test"}, "", nil)
		ownerDone <- fetchErr
	}()
	select {
	case <-fetcher.started:
	case <-time.After(time.Second):
		t.Fatal("single-flight owner did not start")
	}

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	go func() {
		_, _, fetchErr := set.fetch(waiterCtx, assetValue.Locator, "signing_ledger", 1024, []string{"artifacts.example.test"}, "", nil)
		waiterDone <- fetchErr
	}()
	cancelWaiter()
	select {
	case err := <-waiterDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled waiter error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled waiter did not return")
	}
	if fetcher.calls.Load() != 1 {
		t.Fatalf("underlying fetch calls after waiter cancellation = %d, want 1", fetcher.calls.Load())
	}
	close(fetcher.release)
	if err := <-ownerDone; err != nil {
		t.Fatalf("single-flight owner error = %v", err)
	}
}

func TestAssetSetSingleFlightFailureIsNotCached(t *testing.T) {
	value := []byte("shared immutable checkpoint")
	rawURL := "https://artifacts.example.test/checkpoint.json"
	assetValue := asset("sources/example/signing-ledger/checkpoint.json", rawURL, value)
	wantErr := errors.New("temporary fetch failure")
	fetcher := &memoryFetcher{values: map[string][]byte{rawURL: value}, failures: []error{wantErr}}
	set, err := NewAssetSet(AssetSetOptions{
		SourceID: "example", Channel: "stable", AllowedHosts: []string{"artifacts.example.test"},
		Fetcher: fetcher, Assets: []Asset{assetValue},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := set.fetch(context.Background(), assetValue.Locator, "signing_ledger", 1024, []string{"artifacts.example.test"}, "", nil); !errors.Is(err, wantErr) {
		t.Fatalf("failed fetch error = %v, want %v", err, wantErr)
	}
	got, _, err := set.fetch(context.Background(), assetValue.Locator, "signing_ledger", 1024, []string{"artifacts.example.test"}, "", nil)
	if err != nil || !bytes.Equal(got, value) {
		t.Fatalf("retry after failed single-flight bytes=%q error=%v", got, err)
	}
	if len(fetcher.requests) != 2 {
		t.Fatalf("underlying fetch calls = %d, want failed owner plus retry", len(fetcher.requests))
	}
}

func TestAssetSetResolvesExactReleaseArtifacts(t *testing.T) {
	const (
		sourceID  = "example_official"
		channel   = "stable"
		publisher = "example.publisher"
		pluginID  = "example.publisher.weather"
		version   = "1.2.3"
		metaRef   = "sources/example_official/stable/releases/weather-1.2.3.json"
		sigRef    = "sources/example_official/stable/releases/weather-1.2.3.sig"
		pkgRef    = "sources/example_official/stable/packages/weather-1.2.3.redevplugin"
	)
	packageBytes := []byte("package bytes")
	packageTransportDigest := digest(packageBytes)
	packageIdentityDigest := strings.Repeat("3", 64)
	metadata := releasecontract.ReleaseMetadata{
		SchemaVersion: releasecontract.ReleaseMetadataSchemaVersion,
		SourceID:      sourceID, ReleaseMetadataRef: metaRef, PublisherID: publisher, PluginID: pluginID, Version: version,
		DistributionRef:          releasecontract.ReleaseDistributionRef{Distribution: "registry_ref", ArtifactRef: pkgRef},
		Hashes:                   releasecontract.ReleasePackageHashSet{PackageSHA256: "sha256:" + packageIdentityDigest, ManifestSHA256: "sha256:" + strings.Repeat("1", 64), EntriesSHA256: "sha256:" + strings.Repeat("2", 64)},
		ReleaseMetadataSignature: releasecontract.ReleaseMetadataSignatureRef{Algorithm: "ed25519", KeyID: "example_signing", SignatureRef: sigRef, SourcePolicyEpoch: "1", RevocationEpoch: "1"},
		PackageSignature:         releasecontract.PackageReleaseSignatureRef{Algorithm: "ed25519", KeyID: "example_signing", SignatureBundleRef: "sources/example_official/stable/releases/weather-1.2.3.package-signature.json", SourcePolicyEpoch: "1", RevocationEpoch: "1"},
	}
	metadataBytes, err := releasecontract.CanonicalReleaseMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	signatureBytes := make([]byte, 64)
	values := map[string][]byte{
		"https://artifacts.example.test/metadata.json": metadataBytes,
		"https://artifacts.example.test/metadata.sig":  signatureBytes,
		"https://artifacts.example.test/package.zip":   packageBytes,
	}
	fetcher := &memoryFetcher{values: values}
	set, err := NewAssetSet(AssetSetOptions{
		SourceID: sourceID, Channel: channel, AllowedHosts: []string{"artifacts.example.test"}, Fetcher: fetcher,
		Assets: []Asset{
			asset(metaRef, "https://artifacts.example.test/metadata.json", metadataBytes),
			asset(sigRef, "https://artifacts.example.test/metadata.sig", signatureBytes),
			asset(pkgRef, "https://artifacts.example.test/package.zip", packageBytes),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := set.ResolveReleaseArtifact(context.Background(), host.ReleaseArtifactResolveRequest{
		ReleaseRef: host.PluginReleaseRef{
			SourceID: sourceID, Channel: channel, ReleaseMetadataRef: metaRef, ReleaseMetadataSHA256: digest(metadataBytes),
			PublisherID: publisher, PluginID: pluginID, Version: version,
			ExpectedHashes: host.PackageHashSet{PackageSHA256: "sha256:" + packageIdentityDigest, ManifestSHA256: "sha256:" + strings.Repeat("1", 64), EntriesSHA256: "sha256:" + strings.Repeat("2", 64)},
		},
		SourcePolicy: releasecontract.SourcePolicyV3{SourceType: "registry", AllowedArtifactHosts: []string{"artifacts.example.test"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	readback, err := io.ReadAll(io.NewSectionReader(resolved.Reader, 0, resolved.Size))
	if err != nil || string(readback) != string(packageBytes) || resolved.ArtifactSHA256 != packageTransportDigest || len(fetcher.requests) != 3 {
		t.Fatalf("resolved = %#v, readback = %q, requests = %d, err = %v", resolved, readback, len(fetcher.requests), err)
	}
	for _, request := range fetcher.requests {
		if len(request.AllowedHosts) != 1 || request.AllowedHosts[0] != "artifacts.example.test" {
			t.Fatalf("allowed hosts = %#v", request.AllowedHosts)
		}
	}
	if fetcher.requests[2].ExpectedSHA256 != packageTransportDigest {
		t.Fatalf("package transport digest = %s, want %s", fetcher.requests[2].ExpectedSHA256, packageTransportDigest)
	}
}

func TestAssetSetRejectsMutableOrMismatchedProjection(t *testing.T) {
	value := []byte("document")
	fetcher := &memoryFetcher{values: map[string][]byte{"https://artifacts.example.test/document.json": value}}
	_, err := NewAssetSet(AssetSetOptions{SourceID: "example", Channel: "stable", AllowedHosts: []string{"artifacts.example.test"}, Fetcher: fetcher, Assets: []Asset{
		asset("sources/example/root/current.json", "https://artifacts.example.test/document.json", value),
		asset("sources/example/root/current.json", "https://artifacts.example.test/document.json", value),
	}})
	if err == nil {
		t.Fatal("duplicate locator was accepted")
	}

	set, err := NewAssetSet(AssetSetOptions{SourceID: "example", Channel: "stable", AllowedHosts: []string{"artifacts.example.test"}, Fetcher: fetcher, Assets: []Asset{
		asset("sources/example/root/current.json", "https://artifacts.example.test/document.json", value),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := set.fetch(context.Background(), "sources/example/root/current.json", "release_document", 1024, []string{"artifacts.example.test"}, strings.Repeat("f", 64), nil); err != ErrAssetMismatch {
		t.Fatalf("digest mismatch error = %v", err)
	}
}

func asset(locator, rawURL string, value []byte) Asset {
	return Asset{Locator: locator, URL: rawURL, SHA256: digest(value), Size: int64(len(value))}
}

type blockingFetcher struct {
	value   []byte
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (fetcher *blockingFetcher) FetchArtifact(ctx context.Context, request externalsource.ArtifactFetchRequest) (externalsource.ArtifactFetchResult, error) {
	fetcher.calls.Add(1)
	fetcher.started <- struct{}{}
	select {
	case <-fetcher.release:
	case <-ctx.Done():
		return externalsource.ArtifactFetchResult{}, ctx.Err()
	}
	return externalsource.ArtifactFetchResult{Bytes: bytes.Clone(fetcher.value), Source: request.URL, Final: request.URL}, nil
}

func digest(value []byte) string {
	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:])
}
