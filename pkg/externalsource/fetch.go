package externalsource

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
)

const (
	defaultMaxRedirects        = 5
	defaultConnectTimeout      = 10 * time.Second
	defaultTLSHandshakeTimeout = 10 * time.Second
	defaultResponseTimeout     = 20 * time.Second
	defaultTotalTimeout        = 2 * time.Minute
	maxCredentialHeaders       = 32
	maxCredentialHeaderBytes   = 16 << 10
)

// CredentialRequest scopes credentials to one exact origin and source.
type CredentialRequest struct {
	SourceID string
	Origin   Origin
}

// CredentialProvider is called independently for every validated hop. A
// returned header is never forwarded to a different origin.
type CredentialProvider interface {
	CredentialFor(ctx context.Context, request CredentialRequest) (http.Header, error)
}

type FetcherOptions struct {
	Stage        *StageStore
	Resolver     AddressResolver
	Credentials  CredentialProvider
	SourceID     string
	TotalTimeout time.Duration
}

type RedirectHop struct {
	StatusCode int
	From       string
	To         string
}

type FetchRequest struct {
	URL      string
	QuotaKey string
}

type FetchResult struct {
	Artifact  StagedArtifact
	Source    string
	Final     string
	Redirects []RedirectHop
}

type hopRoundTrip func(context.Context, PackageURL, []netip.Addr, http.Header) (*http.Response, error)

type Fetcher struct {
	stage        *StageStore
	resolver     AddressResolver
	credentials  CredentialProvider
	sourceID     string
	totalTimeout time.Duration
	maxRedirects int
	maxBytes     int64
	roundTrip    hopRoundTrip
	rootCAs      *x509.CertPool
}

func NewFetcher(options FetcherOptions) (*Fetcher, error) {
	if options.Stage == nil {
		return nil, invalidSource("new_fetcher", "stage store is required")
	}
	totalTimeout := options.TotalTimeout
	if totalTimeout == 0 {
		totalTimeout = defaultTotalTimeout
	}
	if totalTimeout <= 0 {
		return nil, invalidSource("new_fetcher", "total timeout must be positive")
	}
	fetcher := &Fetcher{
		stage:        options.Stage,
		resolver:     options.Resolver,
		credentials:  options.Credentials,
		sourceID:     strings.TrimSpace(options.SourceID),
		totalTimeout: totalTimeout,
		maxRedirects: defaultMaxRedirects,
		maxBytes:     MaxArtifactBytes,
	}
	fetcher.roundTrip = fetcher.secureRoundTrip
	return fetcher, nil
}

func (fetcher *Fetcher) FetchPackage(ctx context.Context, request FetchRequest) (FetchResult, error) {
	return fetcher.fetchPackage(ctx, request.URL, request.QuotaKey, false)
}

func (fetcher *Fetcher) fetchPackage(ctx context.Context, rawURL, quotaKey string, allowInitialQuery bool) (FetchResult, error) {
	if fetcher == nil || fetcher.stage == nil || fetcher.roundTrip == nil {
		return FetchResult{}, invalidSource("fetch", "fetcher is not initialized")
	}
	releaseFetch, err := fetcher.stage.acquireFetch(quotaKey)
	if err != nil {
		return FetchResult{}, err
	}
	defer releaseFetch()
	current, err := parsePackageURL(rawURL, allowInitialQuery)
	if err != nil {
		return FetchResult{}, err
	}
	sourceDisplay := current.DisplayURL()
	ctx, cancel := context.WithTimeout(ctx, fetcher.totalTimeout)
	defer cancel()
	redirects := make([]RedirectHop, 0, fetcher.maxRedirects)
	visited := map[string]struct{}{current.requestURL().String(): {}}

	for {
		addresses, err := ResolvePublicAddresses(ctx, fetcher.resolver, current)
		if err != nil {
			return FetchResult{}, err
		}
		headers, err := fetcher.credentialHeaders(ctx, current.origin)
		if err != nil {
			return FetchResult{}, err
		}
		response, err := fetcher.roundTrip(ctx, current, addresses, headers)
		if err != nil {
			return FetchResult{}, externalError(ErrorTransport, "fetch", current.DisplayURL(), err)
		}
		if response == nil || response.Body == nil {
			return FetchResult{}, externalError(ErrorTransport, "fetch", current.DisplayURL(), fmt.Errorf("response is missing"))
		}
		if isRedirectStatus(response.StatusCode) {
			next, redirectErr := redirectTarget(current, response)
			_ = response.Body.Close()
			if redirectErr != nil {
				return FetchResult{}, redirectErr
			}
			if len(redirects) >= fetcher.maxRedirects {
				return FetchResult{}, externalError(ErrorTooManyRedirects, "redirect", current.DisplayURL(), fmt.Errorf("redirect limit exceeded"))
			}
			canonical := next.requestURL().String()
			if _, duplicate := visited[canonical]; duplicate {
				return FetchResult{}, externalError(ErrorRedirectDenied, "redirect", next.DisplayURL(), fmt.Errorf("redirect loop"))
			}
			visited[canonical] = struct{}{}
			redirects = append(redirects, RedirectHop{StatusCode: response.StatusCode, From: current.DisplayURL(), To: next.DisplayURL()})
			current = next
			continue
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			return FetchResult{}, externalError(ErrorHTTPStatus, "fetch", current.DisplayURL(), fmt.Errorf("unexpected HTTP status %d", response.StatusCode))
		}
		encoding := strings.TrimSpace(strings.ToLower(response.Header.Get("Content-Encoding")))
		if encoding != "" && encoding != "identity" {
			_ = response.Body.Close()
			return FetchResult{}, externalError(ErrorUnsupportedEncoding, "fetch", current.DisplayURL(), fmt.Errorf("content encoding is not identity"))
		}
		if response.ContentLength > fetcher.maxBytes {
			_ = response.Body.Close()
			return FetchResult{}, externalError(ErrorArtifactTooLarge, "fetch", current.DisplayURL(), fmt.Errorf("content length exceeds limit"))
		}
		artifact, stageErr := fetcher.stage.stageWithLimitForOwner(ctx, quotaKey, response.Body, fetcher.maxBytes)
		closeErr := response.Body.Close()
		if stageErr != nil {
			return FetchResult{}, stageErr
		}
		if closeErr != nil {
			_ = fetcher.stage.Remove(artifact)
			return FetchResult{}, externalError(ErrorTransport, "fetch", current.DisplayURL(), closeErr)
		}
		return FetchResult{Artifact: artifact, Source: sourceDisplay, Final: current.DisplayURL(), Redirects: redirects}, nil
	}
}

func (fetcher *Fetcher) credentialHeaders(ctx context.Context, origin Origin) (http.Header, error) {
	headers := make(http.Header)
	fieldCount := 0
	fieldBytes := 0
	if fetcher.credentials != nil {
		provided, err := fetcher.credentials.CredentialFor(ctx, CredentialRequest{SourceID: fetcher.sourceID, Origin: origin})
		if err != nil {
			return nil, externalError(ErrorCredentialDenied, "credentials", origin.String(), err)
		}
		for name, values := range provided {
			canonical := http.CanonicalHeaderKey(name)
			if !validCredentialHeaderName(canonical) || len(values) == 0 {
				return nil, externalError(ErrorCredentialDenied, "credentials", origin.String(), fmt.Errorf("credential header is invalid"))
			}
			for _, value := range values {
				if !httpguts.ValidHeaderFieldValue(value) {
					return nil, externalError(ErrorCredentialDenied, "credentials", origin.String(), fmt.Errorf("credential header value is invalid"))
				}
				fieldCount++
				fieldBytes += len(canonical) + len(value) + 4
				if fieldCount > maxCredentialHeaders || fieldBytes > maxCredentialHeaderBytes {
					return nil, externalError(ErrorCredentialDenied, "credentials", origin.String(), fmt.Errorf("credential headers exceed limit"))
				}
				headers.Add(canonical, value)
			}
		}
	}
	headers.Set("Accept-Encoding", "identity")
	return headers, nil
}

func validCredentialHeaderName(name string) bool {
	if name == "" || !httpguts.ValidHeaderFieldName(name) {
		return false
	}
	switch name {
	case "Host", "Accept-Encoding", "Connection", "Content-Length", "Expect", "Keep-Alive", "Proxy-Authorization", "Proxy-Connection", "Range", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return false
	default:
		return true
	}
}

func (fetcher *Fetcher) secureRoundTrip(ctx context.Context, locator PackageURL, addresses []netip.Addr, headers http.Header) (*http.Response, error) {
	requestURL := locator.requestURL()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header = headers.Clone()
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           pinnedDialContext(&net.Dialer{Timeout: defaultConnectTimeout}, locator, addresses),
		DisableCompression:    true,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: defaultResponseTimeout,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: locator.origin.Host,
			RootCAs:    fetcher.rootCAs,
		},
	}
	response, err := transport.RoundTrip(request)
	transport.CloseIdleConnections()
	return response, err
}

func redirectTarget(current PackageURL, response *http.Response) (PackageURL, error) {
	locations := response.Header.Values("Location")
	if len(locations) != 1 || strings.TrimSpace(locations[0]) == "" {
		return PackageURL{}, externalError(ErrorRedirectDenied, "redirect", current.DisplayURL(), fmt.Errorf("one Location header is required"))
	}
	reference, err := url.Parse(locations[0])
	if err != nil {
		return PackageURL{}, externalError(ErrorRedirectDenied, "redirect", current.DisplayURL(), err)
	}
	resolved := current.requestURL().ResolveReference(reference)
	next, err := parsePackageURL(resolved.String(), true)
	if err != nil {
		return PackageURL{}, externalError(ErrorRedirectDenied, "redirect", current.DisplayURL(), err)
	}
	return next, nil
}

func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}
