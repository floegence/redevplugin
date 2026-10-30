package plugindata

import (
	"encoding/json"
	"os"
	"testing"
)

func TestRetainedRecoverySharedFixture(t *testing.T) {
	data, err := os.ReadFile("../../spec/plugin/retained-recovery-fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Plan   RetainedRecoveryPlan   `json:"plan"`
		Result RetainedRecoveryResult `json:"result"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	result, err := RetainedRecoveryOutcome(fixture.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if !SameBinding(result.Active, fixture.Result.Active) || !SameBinding(result.Retained, fixture.Result.Retained) || result.ManagementRevision != fixture.Result.ManagementRevision {
		t.Fatalf("fixture result mismatch: %#v", result)
	}
}
