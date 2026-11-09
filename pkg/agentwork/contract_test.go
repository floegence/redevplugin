package agentwork

import (
	"bytes"
	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"os"
	"strings"
	"testing"
)

func TestPublishedContractAndGeneratedClient(t *testing.T) {
	known, err := Contract()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../spec/plugin/agent-work-contract.json")
	if err != nil || !bytes.Equal(raw, contractArtifact) {
		t.Fatal("contract artifact stale", err)
	}
	if len(known.Contract.Methods) != 4 {
		t.Fatal(known.Contract)
	}
	generated, err := capabilitycontract.GenerateTypeScript(known.Contract)
	if err != nil {
		t.Fatal(err)
	}
	generated = []byte(strings.Replace(string(generated), "\"@floegence/redevplugin-ui/plugin\"", "\"./plugin.js\"", 1))
	actual, err := os.ReadFile("../../packages/redevplugin-ui/src/agent-work.gen.ts")
	if err != nil || !bytes.Equal(actual, generated) {
		t.Fatal("SDK stale", err)
	}
	for _, m := range known.Contract.Methods {
		if m.Execution != "sync" || len(m.TargetFields) != 1 || m.TargetFields[0] != "work_id" {
			t.Fatal(m)
		}
		for _, forbidden := range []string{"user_id", "environment_id", "plugin_instance_id", "api_key", "system_prompt", "tools"} {
			if _, ok := m.RequestSchema["properties"].(map[string]any)[forbidden]; ok {
				t.Fatalf("untrusted authority field %s", forbidden)
			}
		}
	}
}
