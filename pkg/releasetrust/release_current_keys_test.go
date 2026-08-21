package releasetrust

import (
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/releasecontract"
)

func TestPreparedReleaseChecksCurrentSigningKeyAuthorization(t *testing.T) {
	prepared := PreparedRelease{snapshot: VerifiedSourceSnapshot{
		policy: releasecontract.SourcePolicyV3{ActiveKeys: releasecontract.SourcePolicyActiveKeys{
			ReleaseMetadata: []string{"release_key"},
			Package:         []string{"package_key"},
		}},
	}}
	if !prepared.AllowsReleaseMetadataSigningKey("release_key") || !prepared.AllowsPackageSigningKey("package_key") {
		t.Fatal("active signing keys were not authorized")
	}
	if prepared.AllowsReleaseMetadataSigningKey("unknown") || prepared.AllowsPackageSigningKey("unknown") {
		t.Fatal("unknown signing key was authorized")
	}
	prepared.snapshot.revocation.RevokedKeyIDs = []string{"release_key", "package_key"}
	if prepared.AllowsReleaseMetadataSigningKey("release_key") || prepared.AllowsPackageSigningKey("package_key") {
		t.Fatal("revoked signing key remained authorized")
	}
}
