package remoterelease

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/testsupport/releasetrustfixture"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/releasetrust"
)

func TestCachedDocumentsRetainTrustVerificationAcrossRestarts(t *testing.T) {
	ctx := context.Background()
	var packaged bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(ctx, "../../testdata/generated_plugins/minimal", &packaged, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"valid", "expired", "revoked", "signature"} {
		t.Run(scenario, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			options := releasetrustfixture.Options{GeneratedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}
			if scenario == "expired" {
				options.GeneratedAt = now.Add(-2 * time.Hour)
				options.ExpiresAt = now.Add(-time.Hour)
			}
			fixture, err := releasetrustfixture.New(packaged.Bytes(), options)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "documents.sqlite")
			cache, err := OpenDocumentCache(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			seed := func(documents map[string][]byte) {
				t.Helper()
				for locator, value := range documents {
					if err := cache.remember(ctx, asset(locator, "https://artifacts.example.test/"+locator, value), value); err != nil {
						t.Fatal(err)
					}
				}
			}
			seed(fixture.DocumentTransport.DocumentBytes())
			if scenario == "revoked" {
				if err := fixture.RevokeRelease(now); err != nil {
					t.Fatal(err)
				}
			}
			documents := fixture.DocumentTransport.DocumentBytes()
			if scenario == "signature" {
				locator := "sources/fixture_source/root/current.json"
				documents[locator] = bytes.Replace(documents[locator], []byte(`"root_epoch":"1"`), []byte(`"root_epoch":"2"`), 1)
			}
			// Current catalog bytes, including an invalid signature, are never authority.
			seed(documents)
			if err := cache.Close(); err != nil {
				t.Fatal(err)
			}
			cache, err = OpenDocumentCache(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer cache.Close()
			assets := make([]Asset, 0, len(documents))
			for locator, value := range documents {
				assets = append(assets, asset(locator, "https://artifacts.example.test/"+locator, value))
			}
			fetcher := &memoryFetcher{values: map[string][]byte{}}
			transport, err := NewAssetSet(AssetSetOptions{SourceID: fixture.Identity.SourceID, Channel: fixture.Identity.Channel, AllowedHosts: []string{"artifacts.example.test"}, Assets: assets, Fetcher: fetcher, DocumentCache: cache})
			if err != nil {
				t.Fatal(err)
			}
			service, err := releasetrust.NewReleaseTrustService(fixture.TrustOptions, releasetrust.ReleaseTrustAdapters{Documents: transport})
			if err != nil {
				t.Fatal(err)
			}
			services, err := releasetrust.NewServiceSet(service)
			if err != nil {
				t.Fatal(err)
			}
			_, err = services.PrepareRelease(ctx, fixture.Identity)
			switch scenario {
			case "valid":
				if err != nil {
					t.Fatal(err)
				}
			case "expired":
				if !errors.Is(err, releasetrust.ErrReleaseTrustExpired) {
					t.Fatalf("expiry: %v", err)
				}
			case "revoked":
				if !errors.Is(err, releasetrust.ErrReleaseTrustRevoked) {
					t.Fatalf("revocation: %v", err)
				}
			case "signature":
				if err == nil {
					t.Fatal("invalid signature was authorized")
				}
			}
			if len(fetcher.requests) != 0 {
				t.Fatalf("restart required %d network requests", len(fetcher.requests))
			}
		})
	}
}
