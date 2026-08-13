package releasepublisher

import (
	"os"
	"strings"
	"testing"
)

func TestReleasePublisherDoesNotDelegateCapabilityPublisherTrust(t *testing.T) {
	raw, err := os.ReadFile("assemble.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, retired := range []string{
		"DelegatedKeyUsageHostCapabilityContract",
		"HostCapabilityContract:",
		"CapabilityPublisherScopes:",
		"capabilityScopes(",
	} {
		if strings.Contains(string(raw), retired) {
			t.Fatalf("release publisher retains retired capability publisher trust %q", retired)
		}
	}
}
