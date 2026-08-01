// Package remoterelease provides a content-addressed remote transport for
// signed ReDevPlugin release assets. It contains no source discovery or trust
// decisions: callers supply an already reviewed locator-to-asset projection.
package remoterelease

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/floegence/redevplugin/pkg/externalsource"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/releasecontract"
	"github.com/floegence/redevplugin/pkg/releasetrust"
)

const maxReleaseSignatureBytes int64 = 64 << 10

var (
	ErrInvalidAssetSet = errors.New("remote release asset set is invalid")
	ErrAssetMissing    = errors.New("remote release asset is missing")
	ErrAssetMismatch   = errors.New("remote release asset identity mismatch")
)

type Asset struct {
	Locator string `json:"locator"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

type AssetFetcher interface {
	FetchArtifact(context.Context, externalsource.ArtifactFetchRequest) (externalsource.ArtifactFetchResult, error)
}

type AssetSetOptions struct {
	SourceID     string
	Channel      string
	QuotaKey     string
	AllowedHosts []string
	Assets       []Asset
	Fetcher      AssetFetcher
}

// AssetSet is an immutable, current-release projection. Updating a catalog
// creates a new set instead of mutating a set used by an in-flight operation.
type AssetSet struct {
	sourceID     string
	channel      string
	quotaKey     string
	allowedHosts []string
	assets       map[string]Asset
	fetcher      AssetFetcher
}

var (
	_ releasetrust.ReleaseDocumentTransport = (*AssetSet)(nil)
	_ releasetrust.SigningLedgerTransport   = (*AssetSet)(nil)
	_ host.ReleaseArtifactResolver          = (*AssetSet)(nil)
)

func NewAssetSet(options AssetSetOptions) (*AssetSet, error) {
	configuration, err := releasetrust.NewSourceConfiguration(options.SourceID, []string{options.Channel})
	if err != nil {
		return nil, ErrInvalidAssetSet
	}
	if _, err := configuration.TrustKey(options.Channel); err != nil || options.Fetcher == nil || len(options.Assets) == 0 {
		return nil, ErrInvalidAssetSet
	}
	hosts, err := validateHosts(options.AllowedHosts)
	if err != nil {
		return nil, err
	}
	assets := make(map[string]Asset, len(options.Assets))
	for _, asset := range options.Assets {
		remoteURL, urlErr := externalsource.ParseDirectPackageURL(asset.URL)
		_, hostAllowed := slices.BinarySearch(hosts, remoteURL.Origin().Host)
		if !validLocator(asset.Locator) || urlErr != nil || !hostAllowed || !validSHA256(asset.SHA256) ||
			asset.Size <= 0 || asset.Size > externalsource.MaxArtifactBytes {
			return nil, ErrInvalidAssetSet
		}
		if _, exists := assets[asset.Locator]; exists {
			return nil, ErrInvalidAssetSet
		}
		assets[asset.Locator] = asset
	}
	return &AssetSet{
		sourceID: options.SourceID, channel: options.Channel, quotaKey: options.QuotaKey,
		allowedHosts: hosts, assets: assets, fetcher: options.Fetcher,
	}, nil
}

func (set *AssetSet) FetchReleaseDocument(ctx context.Context, request releasetrust.ReleaseDocumentRequest) (releasetrust.ReleaseDocumentResult, error) {
	if !set.matches(request.SourceID(), request.Channel()) {
		return releasetrust.ReleaseDocumentResult{}, ErrAssetMissing
	}
	value, digest, err := set.fetch(ctx, request.Locator().String(), request.MaxBytes(), set.allowedHosts, "")
	if err != nil {
		return releasetrust.ReleaseDocumentResult{}, err
	}
	return releasetrust.NewReleaseDocumentResult(request, digest, value)
}

func (set *AssetSet) FetchSigningLedgerArtifact(ctx context.Context, request releasetrust.SigningLedgerRequest) (releasetrust.SigningLedgerResult, error) {
	if !set.matches(request.SourceID(), request.Channel()) {
		return releasetrust.SigningLedgerResult{}, ErrAssetMissing
	}
	value, _, err := set.fetch(ctx, request.Locator().String(), request.MaxBytes(), set.allowedHosts, "")
	if err != nil {
		return releasetrust.SigningLedgerResult{}, err
	}
	return releasetrust.NewSigningLedgerResult(request, value)
}

func (set *AssetSet) ResolveReleaseArtifact(ctx context.Context, request host.ReleaseArtifactResolveRequest) (host.ResolvedPackageArtifact, error) {
	if set == nil || request.SourcePolicy.SourceType != "registry" || request.ReleaseRef.SourceID != set.sourceID ||
		request.ReleaseRef.Channel != set.channel {
		return host.ResolvedPackageArtifact{}, ErrInvalidAssetSet
	}
	hosts, err := validateHosts(request.SourcePolicy.AllowedArtifactHosts)
	if err != nil {
		return host.ResolvedPackageArtifact{}, err
	}
	metadataBytes, _, err := set.fetch(ctx, request.ReleaseRef.ReleaseMetadataRef, releasetrust.MaxReleaseDocumentBytes, hosts, request.ReleaseRef.ReleaseMetadataSHA256)
	if err != nil {
		return host.ResolvedPackageArtifact{}, err
	}
	metadata, err := releasecontract.DecodeReleaseMetadata(metadataBytes)
	if err != nil || metadata.SourceID != request.ReleaseRef.SourceID || metadata.ReleaseMetadataRef != request.ReleaseRef.ReleaseMetadataRef ||
		metadata.PublisherID != request.ReleaseRef.PublisherID || metadata.PluginID != request.ReleaseRef.PluginID || metadata.Version != request.ReleaseRef.Version ||
		metadata.DistributionRef.Distribution != string(host.PackageDistributionRegistryRef) {
		return host.ResolvedPackageArtifact{}, ErrAssetMismatch
	}
	signature, _, err := set.fetch(ctx, metadata.ReleaseMetadataSignature.SignatureRef, maxReleaseSignatureBytes, hosts, "")
	if err != nil {
		return host.ResolvedPackageArtifact{}, err
	}
	if len(signature) != 64 {
		return host.ResolvedPackageArtifact{}, ErrAssetMismatch
	}
	packageBytes, digest, err := set.fetch(ctx, metadata.DistributionRef.ArtifactRef, externalsource.MaxArtifactBytes, hosts, "")
	if err != nil {
		return host.ResolvedPackageArtifact{}, err
	}
	return host.ResolvedPackageArtifact{
		ReleaseMetadataBytes: metadataBytes, ReleaseMetadataSignature: signature,
		Reader: bytes.NewReader(packageBytes), Size: int64(len(packageBytes)), ArtifactSHA256: digest,
	}, nil
}

func (set *AssetSet) matches(sourceID, channel string) bool {
	return set != nil && sourceID == set.sourceID && (channel == "" || channel == set.channel)
}

func (set *AssetSet) fetch(ctx context.Context, locator string, maxBytes int64, allowedHosts []string, expectedSHA256 string) ([]byte, string, error) {
	if set == nil || set.fetcher == nil || maxBytes <= 0 {
		return nil, "", ErrInvalidAssetSet
	}
	asset, ok := set.assets[locator]
	if !ok || asset.Size > maxBytes {
		return nil, "", ErrAssetMissing
	}
	if expectedSHA256 != "" && (strings.TrimPrefix(expectedSHA256, "sha256:") != asset.SHA256) {
		return nil, "", ErrAssetMismatch
	}
	result, err := set.fetcher.FetchArtifact(ctx, externalsource.ArtifactFetchRequest{
		URL: asset.URL, QuotaKey: set.quotaKey, MaxBytes: maxBytes, AllowedHosts: slices.Clone(allowedHosts),
		ExpectedSize: asset.Size, ExpectedSHA256: asset.SHA256,
	})
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(result.Bytes)
	if int64(len(result.Bytes)) != asset.Size || hex.EncodeToString(digest[:]) != asset.SHA256 {
		return nil, "", ErrAssetMismatch
	}
	return slices.Clone(result.Bytes), asset.SHA256, nil
}

func validateHosts(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > 1024 {
		return nil, ErrInvalidAssetSet
	}
	result := slices.Clone(values)
	for index, value := range result {
		if value == "" || value != strings.ToLower(value) || len(value) > 253 ||
			(index > 0 && value <= result[index-1]) {
			return nil, ErrInvalidAssetSet
		}
		for _, label := range strings.Split(value, ".") {
			if len(label) == 0 || len(label) > 63 || !alphaNumeric(label[0]) || !alphaNumeric(label[len(label)-1]) {
				return nil, ErrInvalidAssetSet
			}
			for _, character := range label {
				if character > 0x7f || (!alphaNumeric(byte(character)) && character != '-') {
					return nil, ErrInvalidAssetSet
				}
			}
		}
		parsed, err := url.Parse("https://" + value + "/")
		if err != nil || parsed.Hostname() != value || parsed.Port() != "" {
			return nil, ErrInvalidAssetSet
		}
	}
	return result, nil
}

func alphaNumeric(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9')
}

func validLocator(value string) bool {
	if value == "" || len(value) > 1024 || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\?#") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for _, character := range segment {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') &&
				!strings.ContainsRune("._@+-", character) {
				return false
			}
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
