package main

import (
	"context"
	"net/netip"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
)

// The development policy permits explicit loopback reviews only. Plugin grants,
// exact destination review and socket pinning still belong to the normal Host.
type authorLoopbackPolicy struct{}

func (authorLoopbackPolicy) AuthorizePrivateNetwork(_ context.Context, request host.PrivateNetworkRequest) error {
	for _, raw := range request.PrivatePrefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().IsLoopback() || (prefix.Addr().Is4() && prefix.Bits() < 8) || (prefix.Addr().Is6() && prefix.Bits() != 128) {
			return permissions.ErrPermissionDenied
		}
	}
	return nil
}
