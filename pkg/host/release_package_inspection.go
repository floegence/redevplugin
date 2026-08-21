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

const (
	releasePackageInspectionTTL             = 5 * time.Minute
	maxPendingReleasePackageInspections     = 128
	maxPendingReleasePackageInspectionBytes = int64(256 << 20)
)

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
	PackageBytes int64
}

type releasePackageInspectionStore struct {
	mu           sync.Mutex
	records      map[string]pendingReleasePackageInspection
	expiryTimers map[string]*time.Timer
	packageBytes int64
}

func newReleasePackageInspectionStore() *releasePackageInspectionStore {
	return &releasePackageInspectionStore{
		records:      make(map[string]pendingReleasePackageInspection),
		expiryTimers: make(map[string]*time.Timer),
	}
}

func (s *releasePackageInspectionStore) put(record pendingReleasePackageInspection, now time.Time) {
	if s == nil || strings.TrimSpace(record.Inspection.InspectionID) == "" {
		return
	}
	record.PackageBytes = releasePackageOwnedBytes(record.Package)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(now)
	if _, exists := s.records[record.Inspection.InspectionID]; exists {
		s.deleteLocked(record.Inspection.InspectionID)
	}
	for len(s.records) >= maxPendingReleasePackageInspections ||
		s.packageBytes+record.PackageBytes > maxPendingReleasePackageInspectionBytes {
		oldestID := s.oldestLocked()
		if oldestID == "" {
			break
		}
		s.deleteLocked(oldestID)
	}
	s.records[record.Inspection.InspectionID] = record
	s.packageBytes += record.PackageBytes
	delay := record.Inspection.ExpiresAt.Sub(now)
	if delay < 0 {
		delay = 0
	}
	id := record.Inspection.InspectionID
	expiresAt := record.Inspection.ExpiresAt
	s.expiryTimers[id] = time.AfterFunc(delay, func() {
		s.expire(id, expiresAt)
	})
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
		s.deleteLocked(id)
		return record, ErrReleasePackageInspectionExpired
	}
	if record.Inspection.PluginInstanceID != strings.TrimSpace(pluginInstanceID) ||
		!releasePackageInspectionMatches(record.ReleaseRef, ref) {
		return record, ErrReleasePackageInspectionStale
	}
	s.deleteLocked(id)
	return record, nil
}

func (s *releasePackageInspectionStore) expire(id string, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok || !record.Inspection.ExpiresAt.Equal(expiresAt) {
		return
	}
	s.deleteLocked(id)
}

func (s *releasePackageInspectionStore) pruneExpiredLocked(now time.Time) {
	for id, record := range s.records {
		if !now.Before(record.Inspection.ExpiresAt) {
			s.deleteLocked(id)
		}
	}
}

func (s *releasePackageInspectionStore) oldestLocked() string {
	oldestID := ""
	var oldestExpiry time.Time
	for id, record := range s.records {
		if oldestID == "" || record.Inspection.ExpiresAt.Before(oldestExpiry) {
			oldestID = id
			oldestExpiry = record.Inspection.ExpiresAt
		}
	}
	return oldestID
}

func (s *releasePackageInspectionStore) deleteLocked(id string) {
	record, ok := s.records[id]
	if ok {
		delete(s.records, id)
		s.packageBytes -= record.PackageBytes
		if s.packageBytes < 0 {
			s.packageBytes = 0
		}
	}
	if timer := s.expiryTimers[id]; timer != nil {
		timer.Stop()
		delete(s.expiryTimers, id)
	}
}

func (s *releasePackageInspectionStore) clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	for _, timer := range s.expiryTimers {
		timer.Stop()
	}
	clear(s.records)
	clear(s.expiryTimers)
	s.packageBytes = 0
	s.mu.Unlock()
}

func releasePackageOwnedBytes(pkg pluginpkg.Package) int64 {
	total := int64(len(pkg.CanonicalManifestBytes))
	for path, content := range pkg.Files {
		total += int64(len(path) + len(content))
	}
	for path, content := range pkg.SignatureFiles {
		total += int64(len(path) + len(content))
	}
	return total
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
