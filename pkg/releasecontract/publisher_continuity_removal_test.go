package releasecontract

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestActiveReleaseContractsDoNotExposePublisherContinuity(t *testing.T) {
	for name, value := range map[string]any{
		"RootDelegationInput":   RootDelegationInput{},
		"RootDelegationV1":      RootDelegationV1{},
		"SourcePolicyInput":     SourcePolicyInput{},
		"SourcePolicyV3":        SourcePolicyV3{},
		"ReleasePointerInput":   ReleasePointerInput{},
		"SourcePolicyPointerV2": SourcePolicyPointerV2{},
		"RevocationInput":       RevocationInput{},
		"RevocationV3":          RevocationV3{},
		"RevocationPointerV2":   RevocationPointerV2{},
	} {
		typeOf := reflect.TypeOf(value)
		for _, field := range []string{"PreviousEpoch", "PreviousDocumentSHA256", "PreviousRootEpoch", "PreviousDelegationSHA256"} {
			if _, exists := typeOf.FieldByName(field); exists {
				t.Errorf("%s retains publisher continuity field %s", name, field)
			}
		}
	}

	for _, filename := range []string{"signing.go", "validate.go"} {
		raw, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		for _, retired := range []string{"GenesisPrevious", "validateEpochChain", "PreviousDocumentSHA256", "PreviousDelegationSHA256"} {
			if strings.Contains(string(raw), retired) {
				t.Errorf("%s retains publisher continuity implementation %q", filename, retired)
			}
		}
	}
}
