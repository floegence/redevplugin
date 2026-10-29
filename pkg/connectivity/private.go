package connectivity

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// Private destinations are a separate, explicitly approved connection policy.
// Metadata/link-local, unspecified, multicast and special-use addresses remain
// denied. External package retrieval never receives this authority.
var privateNetworks = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("::1/128"),
}

func ValidatePrivatePrefixes(values []string) error {
	if len(values) == 0 || len(values) > 16 {
		return ErrTargetDenied
	}
	seen := map[string]bool{}
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.String() != value || seen[value] {
			return ErrTargetDenied
		}
		allowed := false
		for _, parent := range privateNetworks {
			if prefix.Addr().BitLen() == parent.Addr().BitLen() && prefix.Bits() >= parent.Bits() && parent.Contains(prefix.Addr()) {
				allowed = true
				break
			}
		}
		if !allowed {
			return ErrTargetDenied
		}
		seen[value] = true
	}
	return nil
}
func privateAddressAllowed(prefixes []string, address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || address.Zone() != "" {
		return false
	}
	for _, raw := range prefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err == nil && prefix.Contains(address) {
			return true
		}
	}
	return false
}
func ValidateApprovedDestination(destination Destination, prefixes []string) error {
	if len(prefixes) == 0 {
		return DefaultClassifier().Evaluate(destination)
	}
	if err := ValidatePrivatePrefixes(prefixes); err != nil {
		return err
	}
	if literal, err := netip.ParseAddr(destination.Host); err == nil && !privateAddressAllowed(prefixes, literal) {
		return ErrTargetDenied
	}
	if _, special := DefaultClassifier().specialHosts[strings.ToLower(destination.Host)]; special && destination.Host != "localhost" {
		return ErrTargetDenied
	}
	return nil
}

type approvedPrivateContextKey struct{}
type approvedPrivateContext struct {
	endpoint string
	prefixes []string
}

func grantNetworkContext(ctx context.Context, grant ConnectionGrant) context.Context {
	if len(grant.PrivatePrefixes) == 0 {
		return ctx
	}
	return context.WithValue(ctx, approvedPrivateContextKey{}, approvedPrivateContext{endpoint: grantEndpoint(grant), prefixes: slices.Clone(grant.PrivatePrefixes)})
}
func evaluateResolvedTarget(ctx context.Context, destination Destination, address netip.Addr) error {
	approved, ok := ctx.Value(approvedPrivateContextKey{}).(approvedPrivateContext)
	if !ok {
		return DefaultClassifier().EvaluateResolvedAddress(destination, address)
	}
	endpoint := net.JoinHostPort(destination.Host, fmt.Sprint(destination.Port))
	if endpoint != approved.endpoint || ValidatePrivatePrefixes(approved.prefixes) != nil || !privateAddressAllowed(approved.prefixes, address) {
		return ErrTargetDenied
	}
	return nil
}
