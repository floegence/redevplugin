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
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v2/pkg/externalsource"
	"github.com/floegence/redevplugin/v2/pkg/host"
	"github.com/floegence/redevplugin/v2/pkg/releasecontract"
	"github.com/floegence/redevplugin/v2/pkg/releasetrust"
)

const maxReleaseSignatureBytes int64 = 64 << 10

const (
	maxFetchAttempts            = 3
	maxRetryAfter               = 10 * time.Second
	maxRetryDelay               = 2 * time.Second
	defaultDocumentFetchTimeout = 20 * time.Second
	defaultPackageFetchTimeout  = 2 * time.Minute
	maxFetchTimeout             = 2 * time.Minute
	defaultAssetCacheMaxBytes   = 128 << 20
)

var (
	ErrInvalidAssetSet = errors.New("remote release asset set is invalid")
	ErrAssetMissing    = errors.New("remote release asset is missing")
	ErrAssetMismatch   = errors.New("remote release asset identity mismatch")
)

type Error struct {
	Phase         string
	ArtifactRole  string
	Retryable     bool
	Attempts      int
	LocatorSHA256 string
	cause         error
}

func (e *Error) Error() string {
	if e == nil {
		return "remote release error"
	}
	return fmt.Sprintf("remote release %s failed for %s after %d attempt(s)", e.Phase, e.ArtifactRole, e.Attempts)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *Error) ReleaseArtifactFailure() host.ReleaseArtifactFailure {
	if e == nil {
		return host.ReleaseArtifactFailure{}
	}
	return host.ReleaseArtifactFailure{
		Phase: e.Phase, ArtifactRole: e.ArtifactRole, Retryable: e.Retryable,
		Attempts: e.Attempts, LocatorSHA256: e.LocatorSHA256,
	}
}

func DetailsOf(err error) (Error, bool) {
	var releaseErr *Error
	if !errors.As(err, &releaseErr) || releaseErr == nil {
		return Error{}, false
	}
	return Error{
		Phase: releaseErr.Phase, ArtifactRole: releaseErr.ArtifactRole,
		Retryable: releaseErr.Retryable, Attempts: releaseErr.Attempts,
		LocatorSHA256: releaseErr.LocatorSHA256,
	}, true
}

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
	FetchTimeout time.Duration
}

// AssetSet is an immutable, current-release projection. Updating a catalog
// creates a new set instead of mutating a set used by an in-flight operation.
type AssetSet struct {
	sourceID      string
	channel       string
	quotaKey      string
	allowedHosts  []string
	assets        map[string]Asset
	fetcher       AssetFetcher
	fetchTimeout  time.Duration
	sleep         func(context.Context, time.Duration) error
	jitter        func(time.Duration) time.Duration
	cacheMu       sync.Mutex
	cache         map[string][]byte
	cacheOrder    []string
	cacheBytes    int64
	cacheMaxBytes int64
	inflight      map[string]*assetFetchFlight
}

type assetFetchFlight struct {
	done   chan struct{}
	value  []byte
	digest string
	err    error
}

var (
	_ releasetrust.ReleaseDocumentTransport = (*AssetSet)(nil)
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
	if options.FetchTimeout < 0 || options.FetchTimeout > maxFetchTimeout {
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
		allowedHosts: hosts, assets: assets, fetcher: options.Fetcher, fetchTimeout: options.FetchTimeout,
		sleep: sleepContext, jitter: retryJitter, cache: make(map[string][]byte), cacheMaxBytes: defaultAssetCacheMaxBytes,
		inflight: make(map[string]*assetFetchFlight),
	}, nil
}

func (set *AssetSet) FetchReleaseDocument(ctx context.Context, request releasetrust.ReleaseDocumentRequest) (releasetrust.ReleaseDocumentResult, error) {
	if !set.matches(request.SourceID(), request.Channel()) {
		return releasetrust.ReleaseDocumentResult{}, ErrAssetMissing
	}
	value, digest, err := set.fetch(ctx, request.Locator().String(), "release_document", request.MaxBytes(), set.allowedHosts, "", nil)
	if err != nil {
		return releasetrust.ReleaseDocumentResult{}, err
	}
	return releasetrust.NewReleaseDocumentResult(request, digest, value)
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
	metadataBytes, _, err := set.fetch(ctx, request.ReleaseRef.ReleaseMetadataRef, "release_metadata", releasetrust.MaxReleaseDocumentBytes, hosts, request.ReleaseRef.ReleaseMetadataSHA256, request.Observe)
	if err != nil {
		return host.ResolvedPackageArtifact{}, err
	}
	metadata, err := releasecontract.DecodeReleaseMetadata(metadataBytes)
	if err != nil || metadata.SourceID != request.ReleaseRef.SourceID || metadata.ReleaseMetadataRef != request.ReleaseRef.ReleaseMetadataRef ||
		metadata.PublisherID != request.ReleaseRef.PublisherID || metadata.PluginID != request.ReleaseRef.PluginID || metadata.Version != request.ReleaseRef.Version ||
		metadata.DistributionRef.Distribution != string(host.PackageDistributionRegistryRef) {
		return host.ResolvedPackageArtifact{}, ErrAssetMismatch
	}
	signature, _, err := set.fetch(ctx, metadata.ReleaseMetadataSignature.SignatureRef, "release_metadata_signature", maxReleaseSignatureBytes, hosts, "", request.Observe)
	if err != nil {
		return host.ResolvedPackageArtifact{}, err
	}
	if len(signature) != 64 {
		return host.ResolvedPackageArtifact{}, ErrAssetMismatch
	}
	packageBytes, digest, err := set.fetch(ctx, metadata.DistributionRef.ArtifactRef, "package", externalsource.MaxArtifactBytes, hosts, "", request.Observe)
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

func (set *AssetSet) fetch(ctx context.Context, locator, artifactRole string, maxBytes int64, allowedHosts []string, expectedSHA256 string, observe func(host.ReleaseArtifactProgress)) ([]byte, string, error) {
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
	if cached, flight, owner := set.acquireAssetFetch(asset); cached != nil {
		if observe != nil {
			observe(host.ReleaseArtifactProgress{
				Phase: "cache_hit", ArtifactRole: artifactRole, Attempt: 1,
				Completed: asset.Size, Total: asset.Size, CacheHit: true,
			})
		}
		return cached, asset.SHA256, nil
	} else if !owner {
		select {
		case <-flight.done:
			if flight.err != nil {
				return nil, "", flight.err
			}
			if observe != nil {
				observe(host.ReleaseArtifactProgress{
					Phase: "cache_hit", ArtifactRole: artifactRole, Attempt: 1,
					Completed: asset.Size, Total: asset.Size, CacheHit: true,
				})
			}
			return slices.Clone(flight.value), flight.digest, nil
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	} else {
		value, digest, err := set.fetchRemoteAsset(ctx, asset, locator, artifactRole, maxBytes, allowedHosts, observe)
		set.finishAssetFetch(asset, flight, value, digest, err)
		return value, digest, err
	}
}

func (set *AssetSet) fetchRemoteAsset(
	ctx context.Context,
	asset Asset,
	locator string,
	artifactRole string,
	maxBytes int64,
	allowedHosts []string,
	observe func(host.ReleaseArtifactProgress),
) ([]byte, string, error) {
	locatorDigest := sha256.Sum256([]byte(locator))
	fetchTimeout := set.fetchTimeout
	if fetchTimeout == 0 {
		fetchTimeout = defaultDocumentFetchTimeout
		if artifactRole == "package" {
			fetchTimeout = defaultPackageFetchTimeout
		}
	}
	fetchCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	var result externalsource.ArtifactFetchResult
	var err error
	for attempt := 1; attempt <= maxFetchAttempts; attempt++ {
		if observe != nil {
			observe(host.ReleaseArtifactProgress{Phase: "download", ArtifactRole: artifactRole, Attempt: attempt, Total: asset.Size})
		}
		result, err = set.fetcher.FetchArtifact(fetchCtx, externalsource.ArtifactFetchRequest{
			URL: asset.URL, QuotaKey: set.quotaKey, MaxBytes: maxBytes, AllowedHosts: slices.Clone(allowedHosts),
			ExpectedSize: asset.Size, ExpectedSHA256: asset.SHA256,
			Progress: func(completed, total int64) {
				if observe != nil {
					observe(host.ReleaseArtifactProgress{Phase: "download", ArtifactRole: artifactRole, Attempt: attempt, Completed: completed, Total: total})
				}
			},
		})
		if err == nil {
			break
		}
		retryable := retryableFetchError(err)
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			// The bounded asset deadline is a transient transport failure. The
			// caller may safely retry the complete trust operation later.
			retryable = true
		}
		if !retryable || attempt == maxFetchAttempts || fetchCtx.Err() != nil {
			return nil, "", &Error{Phase: "fetch", ArtifactRole: artifactRole, Retryable: retryable, Attempts: attempt, LocatorSHA256: hex.EncodeToString(locatorDigest[:]), cause: err}
		}
		delay := retryDelay(attempt, externalsource.RetryAfterOf(err), set.jitter)
		if observe != nil {
			observe(host.ReleaseArtifactProgress{Phase: "retry_wait", ArtifactRole: artifactRole, Attempt: attempt, RetryAfter: delay, Total: asset.Size})
		}
		if sleepErr := set.sleep(fetchCtx, delay); sleepErr != nil {
			return nil, "", &Error{Phase: "retry_wait", ArtifactRole: artifactRole, Retryable: true, Attempts: attempt, LocatorSHA256: hex.EncodeToString(locatorDigest[:]), cause: sleepErr}
		}
	}
	digest := sha256.Sum256(result.Bytes)
	if int64(len(result.Bytes)) != asset.Size || hex.EncodeToString(digest[:]) != asset.SHA256 {
		return nil, "", ErrAssetMismatch
	}
	set.rememberAsset(asset, result.Bytes)
	return slices.Clone(result.Bytes), asset.SHA256, nil
}

func (set *AssetSet) acquireAssetFetch(asset Asset) ([]byte, *assetFetchFlight, bool) {
	set.cacheMu.Lock()
	defer set.cacheMu.Unlock()
	if value, ok := set.cache[asset.SHA256]; ok {
		digest := sha256.Sum256(value)
		if int64(len(value)) == asset.Size && hex.EncodeToString(digest[:]) == asset.SHA256 {
			return slices.Clone(value), nil, false
		}
		delete(set.cache, asset.SHA256)
		set.cacheBytes -= int64(len(value))
		set.removeCacheOrder(asset.SHA256)
	}
	if flight := set.inflight[asset.SHA256]; flight != nil {
		return nil, flight, false
	}
	flight := &assetFetchFlight{done: make(chan struct{})}
	set.inflight[asset.SHA256] = flight
	return nil, flight, true
}

func (set *AssetSet) finishAssetFetch(asset Asset, flight *assetFetchFlight, value []byte, digest string, err error) {
	set.cacheMu.Lock()
	defer set.cacheMu.Unlock()
	flight.value = slices.Clone(value)
	flight.digest = digest
	flight.err = err
	delete(set.inflight, asset.SHA256)
	close(flight.done)
}

func (set *AssetSet) rememberAsset(asset Asset, value []byte) {
	if asset.Size > set.cacheMaxBytes {
		return
	}
	set.cacheMu.Lock()
	defer set.cacheMu.Unlock()
	if _, exists := set.cache[asset.SHA256]; exists {
		return
	}
	for set.cacheBytes+asset.Size > set.cacheMaxBytes && len(set.cacheOrder) > 0 {
		oldest := set.cacheOrder[0]
		set.cacheOrder = set.cacheOrder[1:]
		set.cacheBytes -= int64(len(set.cache[oldest]))
		delete(set.cache, oldest)
	}
	set.cache[asset.SHA256] = slices.Clone(value)
	set.cacheOrder = append(set.cacheOrder, asset.SHA256)
	set.cacheBytes += asset.Size
}

func (set *AssetSet) removeCacheOrder(digest string) {
	for index, value := range set.cacheOrder {
		if value == digest {
			set.cacheOrder = append(set.cacheOrder[:index], set.cacheOrder[index+1:]...)
			return
		}
	}
}

func retryableFetchError(err error) bool {
	switch externalsource.CodeOf(err) {
	case externalsource.ErrorDNS, externalsource.ErrorTransport:
		return true
	case externalsource.ErrorHTTPStatus:
		status := externalsource.HTTPStatusOf(err)
		return status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests || status >= 500
	default:
		return false
	}
}

func retryDelay(attempt int, retryAfter time.Duration, jitter func(time.Duration) time.Duration) time.Duration {
	if retryAfter > 0 {
		return min(retryAfter, maxRetryAfter)
	}
	base := 250 * time.Millisecond * time.Duration(1<<(attempt-1))
	return min(base+jitter(base/4), maxRetryDelay)
}

func retryJitter(maximum time.Duration) time.Duration {
	if maximum <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(maximum) + 1))
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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
