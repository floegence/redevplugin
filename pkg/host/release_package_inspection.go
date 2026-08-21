package host

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/releasecontract"
	"github.com/floegence/redevplugin/v3/pkg/releasetrust"
	"github.com/floegence/redevplugin/v3/pkg/security"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

const releasePackageInspectionTTL = 5 * time.Minute

var (
	ErrReleasePackageInspectionNotFound = errors.New("release package inspection not found")
	ErrReleasePackageInspectionExpired  = errors.New("release package inspection expired")
	ErrReleasePackageInspectionStale    = errors.New("release package inspection is stale")
)

type pendingReleasePackageInspection struct {
	Scope        sessionctx.SessionScope
	Inspection   ReleasePackageInspection
	ReleaseRef   PluginReleaseRef
	Package      pluginpkg.Package
	Release      PluginPackageRelease
	SourcePolicy releasecontract.SourcePolicyV3
	Verified     releasetrust.VerifiedPackage
	Metadata     map[string]string
}

type releasePackageInspectionStore struct {
	mu      sync.Mutex
	records map[string]pendingReleasePackageInspection
}

func newReleasePackageInspectionStore() *releasePackageInspectionStore {
	return &releasePackageInspectionStore{records: make(map[string]pendingReleasePackageInspection)}
}

func (s *releasePackageInspectionStore) put(record pendingReleasePackageInspection) {
	if s == nil || strings.TrimSpace(record.Inspection.InspectionID) == "" {
		return
	}
	s.mu.Lock()
	s.records[record.Inspection.InspectionID] = record
	s.mu.Unlock()
}

func (s *releasePackageInspectionStore) claim(
	id string,
	scope sessionctx.SessionScope,
	pluginInstanceID string,
	ref PluginReleaseRef,
	now time.Time,
) (pendingReleasePackageInspection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id = strings.TrimSpace(id)
	record, ok := s.records[id]
	if !ok || !record.Scope.Matches(scope) {
		return pendingReleasePackageInspection{}, ErrReleasePackageInspectionNotFound
	}
	if !now.Before(record.Inspection.ExpiresAt) {
		delete(s.records, id)
		return record, ErrReleasePackageInspectionExpired
	}
	if record.Inspection.PluginInstanceID != strings.TrimSpace(pluginInstanceID) ||
		!releasePackageInspectionMatches(record.ReleaseRef, ref) {
		return record, ErrReleasePackageInspectionStale
	}
	delete(s.records, id)
	return record, nil
}

func (s *releasePackageInspectionStore) clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	clear(s.records)
	s.mu.Unlock()
}

func releasePackageInspectionMatches(left, right PluginReleaseRef) bool {
	return left.SourceID == right.SourceID && left.Channel == right.Channel &&
		left.ReleaseMetadataRef == right.ReleaseMetadataRef && left.ReleaseMetadataSHA256 == right.ReleaseMetadataSHA256 &&
		left.PublisherID == right.PublisherID && left.PluginID == right.PluginID && left.Version == right.Version &&
		left.ExpectedHashes == right.ExpectedHashes
}

func releasePackageInspectionFailureCode(err error) string {
	switch {
	case errors.Is(err, ErrReleasePackageInspectionExpired):
		return string(security.ErrReleaseInspectionExpired)
	case errors.Is(err, ErrReleasePackageInspectionStale):
		return string(security.ErrReleaseInspectionStale)
	default:
		return string(security.ErrReleaseInspectionExpired)
	}
}

func cloneReleasePackageInspectionMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return nil
	}
	clone := make(map[string]string, len(metadata))
	for key, value := range metadata {
		clone[key] = value
	}
	return clone
}

func (h *Host) refreshReleaseInspectionTrust(ctx context.Context, ref PluginReleaseRef, pending pendingReleasePackageInspection) error {
	if h == nil || h.adapters.ReleaseTrust == nil {
		return ErrReleasePackageInspectionStale
	}
	prepared, err := h.adapters.ReleaseTrust.PrepareRelease(ctx, releasetrust.ReleaseIdentity{
		SourceID: ref.SourceID, Channel: ref.Channel, ReleaseMetadataRef: ref.ReleaseMetadataRef,
		ReleaseMetadataSHA256: ref.ReleaseMetadataSHA256, PublisherID: ref.PublisherID,
		PluginID: ref.PluginID, Version: ref.Version,
	})
	if err != nil {
		return releaseTrustBoundaryError(err)
	}
	document := pending.Verified.ReleaseMetadata().Document()
	if prepared.SourcePolicy().Epoch != pending.SourcePolicy.Epoch ||
		!prepared.AllowsReleaseMetadataSigningKey(document.ReleaseMetadataSignature.KeyID) ||
		!prepared.AllowsPackageSigningKey(document.PackageSignature.KeyID) {
		return ErrReleasePackageInspectionStale
	}
	return nil
}
