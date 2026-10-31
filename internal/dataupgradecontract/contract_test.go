package dataupgradecontract

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSharedDataUpgradeContract(t *testing.T) {
	raw, err := os.ReadFile("../../spec/plugin/data-upgrade-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	type fixture struct {
		Name    string
		Request json.RawMessage
	}
	var fixtures struct{ Valid, Invalid []fixture }
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures.Valid {
		t.Run(f.Name, func(t *testing.T) {
			if err := Validate(f.Request); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, f := range fixtures.Invalid {
		t.Run(f.Name, func(t *testing.T) {
			if err := Validate(f.Request); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}
