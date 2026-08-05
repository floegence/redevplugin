package remoterelease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/externalsource"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/releasecontract"
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
	set.fetcher = permanent
	_, _, err = set.fetch(context.Background(), "sources/example/root/current.json", "release_document", 1024, []string{"artifacts.example.test"}, "", nil)
	var releaseErr *Error
	if !errors.As(err, &releaseErr) || releaseErr.Retryable || releaseErr.Attempts != 1 || len(permanent.requests) != 1 {
		t.Fatalf("permanent error=%#v requests=%d", err, len(permanent.requests))
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
	metadata := releasecontract.ReleaseMetadataV8{
		SchemaVersion: releasecontract.ReleaseMetadataSchemaVersion,
		SourceID:      sourceID, ReleaseMetadataRef: metaRef, PublisherID: publisher, PluginID: pluginID, Version: version,
		DistributionRef:          releasecontract.ReleaseDistributionRef{Distribution: "registry_ref", ArtifactRef: pkgRef},
		Hashes:                   releasecontract.ReleasePackageHashSet{PackageSHA256: "sha256:" + packageIdentityDigest, ManifestSHA256: "sha256:" + strings.Repeat("1", 64), EntriesSHA256: "sha256:" + strings.Repeat("2", 64)},
		ReleaseMetadataSignature: releasecontract.ReleaseMetadataSignatureRef{Algorithm: "ed25519", KeyID: "example_signing", SignatureRef: sigRef, SourcePolicyEpoch: "1", RevocationEpoch: "1"},
		PackageSignature:         releasecontract.PackageReleaseSignatureRef{Algorithm: "ed25519", KeyID: "example_signing", SignatureBundleRef: "sources/example_official/stable/releases/weather-1.2.3.package-signature.json", SourcePolicyEpoch: "1", RevocationEpoch: "1"},
		Compatibility:            releasecontract.ReleaseCompatibility{MinReDevPluginVersion: "0.6.21", MinRuntimeVersion: "0.6.21", UIProtocolVersion: "plugin-ui-v7"},
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
		SourcePolicy: releasecontract.SourcePolicyV2{SourceType: "registry", AllowedArtifactHosts: []string{"artifacts.example.test"}},
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

func digest(value []byte) string {
	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:])
}
