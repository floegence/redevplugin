package agentconversation

import (
	"bytes"
	"crypto/sha256"
	"fmt"
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

func TestOriginalSendOperationsBindRequestIdentity(t *testing.T) {
	known, err := Contract()
	if err != nil {
		t.Fatal(err)
	}
	for name, effect := range map[string]string{"agent.conversation.result": "read", "agent.conversation.cancel_send": "execute"} {
		found := false
		for _, method := range known.Contract.Methods {
			if method.Name != name {
				continue
			}
			found = true
			if method.Effect != effect || strings.Join(method.TargetFields, ",") != "binding_id,conversation_id,request_id" {
				t.Fatalf("wrong original send boundary: %+v", method)
			}
		}
		if !found {
			t.Errorf("missing %s", name)
		}
	}
}

func TestConversationContractRetainsPublishedClientIdentity(t *testing.T) {
	contracts, err := SupportedContracts()
	if err != nil || len(contracts) != 5 {
		t.Fatalf("supported contracts: %v", err)
	}
	registry := capabilitycontract.NewRegistry()
	for _, known := range contracts {
		if err := registry.Add(known); err != nil {
			t.Fatal(err)
		}
	}
	for _, known := range contracts {
		if _, err := registry.Require(known.Pin); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile("../../spec/plugin/agent-conversation-1.0.0-contract.json")
	if err != nil || !bytes.Equal(raw, contractV1Artifact) {
		t.Fatal("retained artifact changed", err)
	}
	if contracts[0].Pin.ContractVersion != "1.4.0" || contracts[1].Pin.ArtifactSHA256 != "2d370b13db27b45bdb8efc43ed87564a7e9be13cb93068d996850a14d807598d" {
		t.Fatal("changed the published 1.3 contract")
	}
	contracts = contracts[1:]
	if contracts[0].Pin.ContractVersion != "1.3.0" || contracts[1].Pin.ContractVersion != "1.2.0" || contracts[1].Pin.ArtifactSHA256 != "2f3f057e2677fa278832d61bac30db20152b7e4ec56771a34773b96b10509de8" || contracts[2].Pin.ContractVersion != "1.1.0" || contracts[2].Pin.ArtifactSHA256 != "4b4275141035edfbd30e343b82fd943c2831f5a8f329d6a983f7455103e046fa" || contracts[3].Pin.ContractVersion != "1.0.0" || contracts[3].Pin.ArtifactSHA256 != fmt.Sprintf("%x", sha256.Sum256(raw)) {
		t.Fatal("contract versions lost their exact identity")
	}
	if contracts[3].Pin.ArtifactSHA256 != "2f48e3fc1bf580893a4a6bd9694cb0b95480c366d4968776c41a2924440e1d26" {
		t.Fatal("the immutable 3.30 conversation contract was rewritten")
	}
}
