package sessionscope

import (
	"os"
	"strings"
	"testing"
)

func TestCurrentSessionTeardownHasOneExecutionLifecycle(t *testing.T) {
	for _, name := range []string{"sessionscope.go", "sqlite.go"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, retired := range []string{
			"StreamTickets",
			"PhaseOperation",
			"PhaseStream",
			"Counts.Operations",
			"Counts.Streams",
		} {
			if strings.Contains(string(raw), retired) {
				t.Fatalf("%s retains retired parallel lifecycle %q", name, retired)
			}
		}
	}
}
