package host_test

import (
	"os"
	"strings"
	"testing"
)

func TestCapabilityExecutionRuntimeHasOneExecutionSinkAndIndex(t *testing.T) {
	source, err := os.ReadFile("capability_execution.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, retired := range []string{
		`"github.com/floegence/redevplugin/v3/pkg/operation"`,
		`"github.com/floegence/redevplugin/v3/pkg/stream"`,
		"hostOperationSink",
		"hostStreamSink",
		"operations map[",
		"streams map[",
		`"operation_id"`,
	} {
		if strings.Contains(text, retired) {
			t.Errorf("active Host execution runtime still contains retired split owner %q", retired)
		}
	}
}

func TestWorkerRuntimeContractUsesOnlyExecutionIdentity(t *testing.T) {
	source, err := os.ReadFile("host.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, retired := range []string{
		"`json:\"operation_id,omitempty\"`",
		"`json:\"stream_id,omitempty\"`",
		"lease.OperationID",
		"lease.StreamID",
		"payload.OperationID",
		"payload.StreamID",
	} {
		if strings.Contains(text, retired) {
			t.Errorf("active worker runtime contract retains retired lifecycle identity %q", retired)
		}
	}
	if !strings.Contains(text, "`json:\"execution_id,omitempty\"`") {
		t.Error("active worker runtime contract does not carry execution_id")
	}
}
