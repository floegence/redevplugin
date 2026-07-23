package externalsource

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/floegence/redevplugin/pkg/connectivity"
)

// AddressResolver permits host products and tests to supply DNS while keeping
// address classification and pinning inside ReDevPlugin.
type AddressResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type systemAddressResolver struct{ resolver *net.Resolver }

func (resolver systemAddressResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return resolver.resolver.LookupNetIP(ctx, network, host)
}

// ResolvePublicAddresses resolves and validates every returned A/AAAA address.
// A mixed public/private answer rejects the entire hop.
func ResolvePublicAddresses(ctx context.Context, resolver AddressResolver, locator PackageURL) ([]netip.Addr, error) {
	requestURL := locator.requestURL()
	if requestURL == nil {
		return nil, externalError(ErrorInvalidURL, "resolve", "", fmt.Errorf("URL is not initialized"))
	}
	host := locator.origin.Host
	var addresses []netip.Addr
	if literal, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{literal}
	} else {
		if resolver == nil {
			resolver = systemAddressResolver{resolver: net.DefaultResolver}
		}
		var err error
		addresses, err = resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, externalError(ErrorDNS, "resolve", locator.DisplayURL(), err)
		}
	}
	if len(addresses) == 0 {
		return nil, externalError(ErrorDNS, "resolve", locator.DisplayURL(), fmt.Errorf("host resolved to no addresses"))
	}
	classifier := connectivity.DefaultClassifier()
	destination := connectivity.Destination{
		Transport: connectivity.TransportHTTP,
		Scheme:    "https",
		Host:      host,
		Port:      int(locator.origin.Port),
	}
	unique := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if !address.IsValid() || address.Zone() != "" {
			return nil, externalError(ErrorTargetBlocked, "resolve", locator.DisplayURL(), fmt.Errorf("resolved address is invalid"))
		}
		address = address.Unmap()
		if !address.IsGlobalUnicast() || classifier.EvaluateResolvedAddress(destination, address) != nil {
			return nil, externalError(ErrorTargetBlocked, "resolve", locator.DisplayURL(), fmt.Errorf("resolved address is not public"))
		}
		unique[address] = struct{}{}
	}
	result := make([]netip.Addr, 0, len(unique))
	for address := range unique {
		result = append(result, address)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Compare(result[right]) < 0 })
	return result, nil
}

func pinnedDialContext(dialer *net.Dialer, locator PackageURL, addresses []netip.Addr) func(context.Context, string, string) (net.Conn, error) {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if !strings.HasPrefix(strings.ToLower(network), "tcp") {
			return nil, externalError(ErrorTransport, "dial", locator.DisplayURL(), fmt.Errorf("non-TCP transport requested"))
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil || !strings.EqualFold(strings.Trim(host, "[]"), locator.origin.Host) || port != fmt.Sprint(locator.origin.Port) {
			return nil, externalError(ErrorTransport, "dial", locator.DisplayURL(), fmt.Errorf("transport changed the validated origin"))
		}
		var failures []error
		for _, pinned := range addresses {
			connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(pinned.String(), port))
			if dialErr == nil {
				return connection, nil
			}
			failures = append(failures, dialErr)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		return nil, externalError(ErrorTransport, "dial", locator.DisplayURL(), fmt.Errorf("all pinned addresses failed: %d", len(failures)))
	}
}
