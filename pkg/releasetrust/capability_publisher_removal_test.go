package releasetrust

import (
	"os"
	"strings"
	"testing"
)

func TestReleaseTrustDoesNotVerifyIndependentlyPublishedCapabilityContracts(t *testing.T) {
	raw, err := os.ReadFile("release.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, retired := range []string{
		"VerifyCapabilityContract",
		"capabilityPublisherAllowed",
		"DelegatedKeyUsageHostCapabilityContract",
	} {
		if strings.Contains(string(raw), retired) {
			t.Fatalf("release trust retains retired capability publisher path %q", retired)
		}
	}
}
