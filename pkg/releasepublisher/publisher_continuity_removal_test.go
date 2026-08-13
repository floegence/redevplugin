package releasepublisher

import (
	"os"
	"strings"
	"testing"
)

func TestPublisherDoesNotEmitContinuityPredecessors(t *testing.T) {
	raw, err := os.ReadFile("assemble.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, retired := range []string{"GenesisPrevious", "PreviousEpoch", "PreviousDocumentSHA256", "PreviousRootEpoch", "PreviousDelegationSHA256"} {
		if strings.Contains(string(raw), retired) {
			t.Errorf("publisher assembly retains continuity predecessor %q", retired)
		}
	}
}
