package host

import (
	"errors"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/releasecontract"
	"github.com/floegence/redevplugin/v3/pkg/version"
)

func TestValidateReleaseRefRequiresStrictSemVer(t *testing.T) {
	ref := PluginReleaseRef{
		SourceID:              "official",
		Channel:               "stable",
		ReleaseMetadataRef:    "plugins/example/release.json",
		ReleaseMetadataSHA256: strings.Repeat("a", 64),
		PublisherID:           "example",
		PluginID:              "com.example.plugin",
		Version:               "1.0",
		ExpectedHashes: PackageHashSet{
			PackageSHA256:  strings.Repeat("b", 64),
			ManifestSHA256: strings.Repeat("c", 64),
			EntriesSHA256:  strings.Repeat("d", 64),
		},
	}
	if err := validateReleaseRef(ref); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("validateReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestReleaseSourcePolicyUsesSemVerPrecedence(t *testing.T) {
	blocked := releasecontract.SourcePolicyV3{DowngradePolicy: "block"}
	for _, testCase := range []struct {
		name    string
		current string
		next    string
	}{
		{name: "stable succeeds prerelease", current: "1.0.0-rc.1", next: "1.0.0"},
		{name: "build metadata does not affect precedence", current: "1.0.0+build.9", next: "1.0.0+build.1"},
		{name: "unbounded major comparison", current: "999999999999999999999999.0.0", next: "1000000000000000000000000.0.0"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := enforceReleaseSourcePolicy(
				PackageTrustActionUpdate,
				&registry.PluginRecord{Version: testCase.current},
				PluginReleaseRef{Version: testCase.next},
				blocked,
			)
			if err != nil {
				t.Fatalf("enforceReleaseSourcePolicy() error = %v", err)
			}
		})
	}
}

func TestReleaseSourcePolicyRejectsInvalidSemVer(t *testing.T) {
	err := enforceReleaseSourcePolicy(
		PackageTrustActionUpdate,
		&registry.PluginRecord{Version: "1.0.0"},
		PluginReleaseRef{Version: "next"},
		releasecontract.SourcePolicyV3{},
	)
	if !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("enforceReleaseSourcePolicy() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestReleaseSourcePolicyTreatsPrereleaseAsDowngradeFromStable(t *testing.T) {
	err := enforceReleaseSourcePolicy(
		PackageTrustActionUpdate,
		&registry.PluginRecord{Version: "1.0.0"},
		PluginReleaseRef{Version: "1.0.0-rc.1"},
		releasecontract.SourcePolicyV3{DowngradePolicy: "block"},
	)
	if !errors.Is(err, ErrReleaseRefPolicyDenied) {
		t.Fatalf("enforceReleaseSourcePolicy() error = %v, want ErrReleaseRefPolicyDenied", err)
	}
}

func TestSelectVersionSnapshotRejectsNonCanonicalSemVer(t *testing.T) {
	_, _, err := selectVersionSnapshot(
		[]registry.PluginVersion{{Version: "1.0.0", PackageHash: "sha256:package"}},
		" 1.0.0",
		"",
	)
	if !errors.Is(err, version.ErrInvalidSemVer) {
		t.Fatalf("selectVersionSnapshot() error = %v, want ErrInvalidSemVer", err)
	}
}
