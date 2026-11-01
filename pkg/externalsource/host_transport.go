package externalsource

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"reflect"
)

// prepareHostTransport preserves host routing while keeping the shared Go
// transport TLS and identity-encoding contract. Native host transports own
// equivalent behavior behind RoundTripper; they must not follow redirects or
// attach ambient credentials. Caller network policy is preserved.
func prepareHostTransport(transport http.RoundTripper) (http.RoundTripper, error) {
	if transport == nil {
		return nil, nil
	}
	value := reflect.ValueOf(transport)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil, invalidSource("host_transport", "transport is nil")
		}
	}
	if base, ok := transport.(*http.Transport); ok {
		configured := base.Clone()
		if configured.TLSClientConfig == nil {
			configured.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			configured.TLSClientConfig = configured.TLSClientConfig.Clone()
			if configured.TLSClientConfig.InsecureSkipVerify {
				return nil, externalError(ErrorInvalidSource, "host_transport", "", fmt.Errorf("TLS verification is required"))
			}
			if configured.TLSClientConfig.MinVersion < tls.VersionTLS12 {
				configured.TLSClientConfig.MinVersion = tls.VersionTLS12
			}
		}
		configured.DisableCompression = true
		if configured.IdleConnTimeout == 0 {
			configured.IdleConnTimeout = pinnedTransportIdleTimeout
		}
		return configured, nil
	}
	return transport, nil
}
