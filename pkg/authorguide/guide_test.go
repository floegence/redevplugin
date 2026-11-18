package authorguide

import (
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/agentconversation"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/version"
)

func TestPublishedGuidesBindExactContractAndIndependentCopies(t *testing.T) {
	known, err := agentconversation.SupportedContracts()
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range Catalog() {
		document, err := Read(reference.ID)
		if err != nil || document.Content == "" || document.PlatformVersion != version.CurrentPlatformVersion() {
			t.Fatal("missing released guide", reference, err)
		}
	}
	document, err := Read("agent-conversation")
	if err != nil || document.Binding.Contract != known[0].Pin || len(document.Methods) != len(known[0].Contract.Methods) {
		t.Fatal("guide does not match published contract", err)
	}
	for i, method := range document.Methods {
		published := known[0].Contract.Methods[i]
		if method.Declaration.Method != published.Name || method.Declaration.Route.Kind != manifest.MethodRouteCapability || method.Declaration.Route.BindingID != document.Binding.BindingID || method.Declaration.Route.TargetMethod != published.Name || !reflect.DeepEqual(method.RequiredPermissions, append([]string{}, published.RequiredPermissions...)) {
			t.Fatalf("stale declaration or permission example: %+v", method)
		}
		if published.Name == "agent.conversation.configure" && !method.ConfirmationRequired {
			t.Fatal("trusted configuration confirmation omitted")
		}
	}
	document.Methods[0].RequiredPermissions[0] = "tampered"
	fresh, _ := Read("agent-conversation")
	if fresh.Methods[0].RequiredPermissions[0] == "tampered" {
		t.Fatal("caller changed authoritative documentation")
	}
	for _, id := range []string{"../host-agent-conversations", "", "https://example.com/guide"} {
		if _, err := Read(id); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("uncatalogued document accepted", id, err)
		}
	}
	for _, text := range []string{"manifest capability routes still must be declared", "trusted host configuration", "not universal model", "cannot\nbootstrap missing plugin grants"} {
		if !strings.Contains(fresh.Content, text) {
			t.Fatal("author boundary is missing", text)
		}
	}
	capabilities, err := Read("capabilities")
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"grantable_permissions", "installation consent", "opening the installed instance", "Preview grants never transfer"} {
		if !strings.Contains(capabilities.Content, text) {
			t.Fatal("installation author guidance missing", text)
		}
	}
}
