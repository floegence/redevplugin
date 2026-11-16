package agentconversation

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
)

func TestPublishedConversationAuthorityAndSDK(t *testing.T) {
	known, err := Contract()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../spec/plugin/agent-conversation-contract.json")
	if err != nil || !bytes.Equal(raw, contractArtifact) {
		t.Fatal("published artifact is stale", err)
	}
	client, err := capabilitycontract.GenerateTypeScript(known.Contract)
	if err != nil {
		t.Fatal(err)
	}
	client = bytes.Replace(client, []byte("\"@floegence/redevplugin-ui/plugin\""), []byte("\"./plugin.js\""), 1)
	generated, err := os.ReadFile("../../packages/redevplugin-ui/src/agent-conversation.gen.ts")
	if err != nil || !bytes.Equal(client, generated) {
		t.Fatal("SDK is stale", err)
	}
	for _, method := range known.Contract.Methods {
		properties := method.RequestSchema["properties"].(map[string]any)
		for _, field := range []string{"owner_user", "user_id", "environment_id", "plugin_instance_id", "api_key", "gateway_token", "execution_binding"} {
			if _, ok := properties[field]; ok {
				t.Errorf("%s accepts untrusted authority %s", method.Name, field)
			}
		}
		if len(method.TargetFields) == 0 {
			t.Errorf("%s has no resource boundary", method.Name)
		}
		if method.Name == "agent.conversation.approve" || method.Name == "agent.conversation.configure" {
			if method.Confirmation == nil || method.Confirmation.Mode != "required" || len(method.Confirmation.RequestHashFields) != len(properties) {
				t.Errorf("%s does not bind trusted confirmation to its exact payload", method.Name)
			}
		}
		if strings.HasPrefix(method.Name, "agent.conversation.client.") && method.Name != "agent.conversation.client.observe" {
			if !strings.HasSuffix(method.Name, "."+method.Effect) {
				t.Errorf("client effect mismatch: %s", method.Name)
			}
		}
		if method.Execution == "subscription" && (method.Effect != "read" || method.CancelPolicy == nil || method.CancelPolicy.DisableBehavior != "cancel") {
			t.Errorf("observation grants execution: %s", method.Name)
		}
	}
}
