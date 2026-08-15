package releasetrust

import (
	"slices"
	"time"

	"github.com/floegence/redevplugin/v2/pkg/releasecontract"
)

type VerifiedSourceSnapshot struct {
	key        SourceTrustKey
	root       releasecontract.RootDelegationV1
	policy     releasecontract.SourcePolicyV2
	revocation releasecontract.RevocationV2
	verifiedAt time.Time
	service    *ReleaseTrustService
}

func (snapshot VerifiedSourceSnapshot) SourceTrustKey() SourceTrustKey { return snapshot.key }
func (snapshot VerifiedSourceSnapshot) VerifiedAt() time.Time          { return snapshot.verifiedAt }

func (snapshot VerifiedSourceSnapshot) RootDelegation() releasecontract.RootDelegationV1 {
	value := snapshot.root
	value.DelegatedKeys = cloneRootDelegatedKeys(value.DelegatedKeys)
	return value
}

func (snapshot VerifiedSourceSnapshot) SourcePolicy() releasecontract.SourcePolicyV2 {
	value := snapshot.policy
	value.AllowedPublishers = slices.Clone(value.AllowedPublishers)
	value.AllowedArtifactHosts = slices.Clone(value.AllowedArtifactHosts)
	value.ActiveKeys.Package = slices.Clone(value.ActiveKeys.Package)
	value.ActiveKeys.ReleaseMetadata = slices.Clone(value.ActiveKeys.ReleaseMetadata)
	value.ActiveKeys.SourcePolicyPointer = slices.Clone(value.ActiveKeys.SourcePolicyPointer)
	value.ActiveKeys.Revocation = slices.Clone(value.ActiveKeys.Revocation)
	value.ActiveKeys.RevocationPointer = slices.Clone(value.ActiveKeys.RevocationPointer)
	return value
}

func (snapshot VerifiedSourceSnapshot) Revocation() releasecontract.RevocationV2 {
	value := snapshot.revocation
	value.RevokedKeyIDs = slices.Clone(value.RevokedKeyIDs)
	value.RevokedReleases = slices.Clone(value.RevokedReleases)
	return value
}

func cloneRootDelegatedKeys(values []releasecontract.RootDelegatedKey) []releasecontract.RootDelegatedKey {
	result := make([]releasecontract.RootDelegatedKey, len(values))
	for index, value := range values {
		value.Usages = slices.Clone(value.Usages)
		value.Channels = slices.Clone(value.Channels)
		result[index] = value
	}
	return result
}

func cloneVerifiedSourceSnapshot(snapshot VerifiedSourceSnapshot) VerifiedSourceSnapshot {
	snapshot.root.DelegatedKeys = cloneRootDelegatedKeys(snapshot.root.DelegatedKeys)
	snapshot.policy = snapshot.SourcePolicy()
	snapshot.revocation = snapshot.Revocation()
	return snapshot
}
