package externalsource

import (
	"context"
	"net/netip"
	"testing"
)

type staticResolver map[string][]netip.Addr

func (resolver staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return resolver[host], nil
}

func TestResolvePublicAddressesRejectsMixedOrSpecialUseAnswers(t *testing.T) {
	locator, err := ParseDirectPackageURL("https://example.com/plugin.redevplugin")
	if err != nil {
		t.Fatal(err)
	}
	tests := [][]netip.Addr{
		{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.0.0.1")},
		{netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("169.254.169.254")},
		{netip.MustParseAddr("100.64.0.1")},
		{netip.MustParseAddr("fc00::1")},
		{netip.MustParseAddr("2001:db8::1")},
	}
	for _, addresses := range tests {
		_, err := ResolvePublicAddresses(context.Background(), staticResolver{"example.com": addresses}, locator)
		if CodeOf(err) != ErrorTargetBlocked {
			t.Fatalf("addresses %v: code = %q, want %q (err=%v)", addresses, CodeOf(err), ErrorTargetBlocked, err)
		}
	}
}

func TestResolvePublicAddressesDeduplicatesAndSorts(t *testing.T) {
	locator, err := ParseDirectPackageURL("https://example.com/plugin.redevplugin")
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := ResolvePublicAddresses(context.Background(), staticResolver{"example.com": {
		netip.MustParseAddr("2606:4700:4700::1111"),
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("1.1.1.1"),
	}}, locator)
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 2 || addresses[0].String() != "1.1.1.1" || addresses[1].String() != "2606:4700:4700::1111" {
		t.Fatalf("addresses = %v", addresses)
	}
}
