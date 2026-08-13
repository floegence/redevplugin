package bridge

import (
	"os"
	"strings"
	"testing"
)

func TestCurrentBridgeHasNoLegacyStreamTicketLifecycle(t *testing.T) {
	for _, name := range []string{"bridge.go", "surface.go"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, retired := range []string{
			"TokenKindStreamTicket",
			"MintStreamTicket",
			"ValidateStreamTicket",
			"ValidateBoundStreamTicket",
			"InspectBoundStreamTicket",
			"RevokeStreamTicketID",
		} {
			if strings.Contains(string(raw), retired) {
				t.Fatalf("%s retains retired stream-ticket lifecycle %q", name, retired)
			}
		}
	}
}

func TestRuntimeExecutionLeaseUsesOnlyExecutionIdentity(t *testing.T) {
	raw, err := os.ReadFile("surface.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, retired := range []string{
		"`json:\"operation_id,omitempty\"`",
		"`json:\"stream_id,omitempty\"`",
		"req.OperationID",
		"req.StreamID",
	} {
		if strings.Contains(text, retired) {
			t.Errorf("runtime execution lease retains retired lifecycle identity %q", retired)
		}
	}
	if !strings.Contains(text, "`json:\"execution_id,omitempty\"`") {
		t.Error("runtime execution lease does not carry execution_id")
	}
}
