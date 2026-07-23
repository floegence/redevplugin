package externalsource

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

const maxSourceURLBytes = 4096

// Origin identifies the exact credential and transport origin for one hop.
type Origin struct {
	Scheme string
	Host   string
	Port   uint16
}

func (origin Origin) String() string {
	return origin.Scheme + "://" + net.JoinHostPort(origin.Host, strconv.Itoa(int(origin.Port)))
}

// PackageURL is a validated public-HTTPS package locator. DisplayURL never
// contains userinfo, query, or fragment data.
type PackageURL struct {
	value      *url.URL
	displayURL string
	origin     Origin
}

func (locator PackageURL) DisplayURL() string { return locator.displayURL }
func (locator PackageURL) Origin() Origin     { return locator.origin }

func (locator PackageURL) requestURL() *url.URL {
	if locator.value == nil {
		return nil
	}
	clone := *locator.value
	return &clone
}

// ParseDirectPackageURL validates the v1 direct-package source. Query strings
// are rejected because credentials and version selectors belong in host-owned
// adapters rather than persisted source locators.
func ParseDirectPackageURL(raw string) (PackageURL, error) {
	return parsePackageURL(raw, false)
}

func parsePackageURL(raw string, allowQuery bool) (PackageURL, error) {
	operation := "parse_url"
	if raw == "" || strings.TrimSpace(raw) != raw || len(raw) > maxSourceURLBytes || !utf8.ValidString(raw) || containsControl(raw) {
		return PackageURL{}, externalError(ErrorInvalidURL, operation, "", fmt.Errorf("URL is empty, non-canonical, or too long"))
	}
	if strings.Contains(raw, "\\") {
		return PackageURL{}, externalError(ErrorInvalidURL, operation, "", fmt.Errorf("backslashes are not allowed"))
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Opaque != "" {
		return PackageURL{}, externalError(ErrorInvalidURL, operation, "", fmt.Errorf("absolute URL is required"))
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return PackageURL{}, externalError(ErrorInvalidURL, operation, "", fmt.Errorf("HTTPS is required"))
	}
	if parsed.User != nil || parsed.Fragment != "" || parsed.ForceQuery || (!allowQuery && parsed.RawQuery != "") {
		return PackageURL{}, externalError(ErrorInvalidURL, operation, "", fmt.Errorf("userinfo, query, or fragment is not allowed"))
	}
	host := parsed.Hostname()
	if host == "" || strings.Contains(host, "%") || containsControl(host) {
		return PackageURL{}, externalError(ErrorInvalidURL, operation, "", fmt.Errorf("host is invalid"))
	}
	asciiHost, err := idna.Lookup.ToASCII(strings.TrimSuffix(host, "."))
	if err != nil || asciiHost == "" || len(asciiHost) > 253 {
		return PackageURL{}, externalError(ErrorInvalidURL, operation, "", fmt.Errorf("host is invalid"))
	}
	asciiHost = strings.ToLower(asciiHost)
	portNumber := 443
	if portText := parsed.Port(); portText != "" {
		portNumber, err = strconv.Atoi(portText)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return PackageURL{}, externalError(ErrorInvalidURL, operation, "", fmt.Errorf("port is invalid"))
		}
	}

	cleanPath, err := canonicalURLPath(parsed)
	if err != nil {
		return PackageURL{}, externalError(ErrorInvalidURL, operation, "", err)
	}
	normalized := &url.URL{
		Scheme:   "https",
		Host:     net.JoinHostPort(asciiHost, strconv.Itoa(portNumber)),
		Path:     cleanPath,
		RawQuery: parsed.RawQuery,
	}
	display := *normalized
	display.RawQuery = ""
	return PackageURL{
		value:      normalized,
		displayURL: display.String(),
		origin:     Origin{Scheme: "https", Host: asciiHost, Port: uint16(portNumber)},
	}, nil
}

func canonicalURLPath(parsed *url.URL) (string, error) {
	escaped := strings.ToLower(parsed.EscapedPath())
	for _, forbidden := range []string{"%00", "%2f", "%5c"} {
		if strings.Contains(escaped, forbidden) {
			return "", fmt.Errorf("encoded path delimiter is not allowed")
		}
	}
	value := parsed.Path
	if value == "" {
		value = "/"
	}
	if !utf8.ValidString(value) || containsControl(value) || strings.Contains(value, "\\") {
		return "", fmt.Errorf("path is invalid")
	}
	cleaned := path.Clean(value)
	if !strings.HasPrefix(cleaned, "/") || cleaned != value {
		return "", fmt.Errorf("path must be canonical")
	}
	return cleaned, nil
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
