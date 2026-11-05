package host

import (
	"errors"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/version"
)

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
