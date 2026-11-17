// Package authorguide publishes version-bound author documentation for host
// tools. Contract examples are derived from the shipped immutable artifacts.
package authorguide

import (
	"embed"
	"fmt"
	"io/fs"

	"github.com/floegence/redevplugin/v3/pkg/agentconversation"
	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/version"
)

//go:embed *.md
var guides embed.FS

type Reference struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type Document struct {
	PlatformVersion string                      `json:"platform_version"`
	Reference       Reference                   `json:"document"`
	Content         string                      `json:"content"`
	Binding         *manifest.CapabilityBinding `json:"binding,omitempty"`
	Methods         []Method                    `json:"methods,omitempty"`
}

type Method struct {
	Declaration          manifest.MethodSpec `json:"declaration"`
	Effect               string              `json:"effect"`
	RequiredPermissions  []string            `json:"required_permissions"`
	ConfirmationRequired bool                `json:"confirmation_required"`
}

func Catalog() []Reference {
	return []Reference{{ID: "capabilities", Title: "Capability declarations, authorization and inspection"},
		{ID: "agent-conversation", Title: "Scoped Agent conversations and trusted configuration"}}
}

// Read accepts only a catalog ID, never a path or an arbitrary URL. Returned
// methods are declaration examples, not selected methods or permission grants.
func Read(id string) (Document, error) {
	var reference Reference
	for _, candidate := range Catalog() {
		if candidate.ID == id {
			reference = candidate
		}
	}
	if reference.ID == "" {
		return Document{}, fmt.Errorf("author guide %q: %w", id, fs.ErrNotExist)
	}
	content, err := guides.ReadFile(id + ".md")
	if err != nil {
		return Document{}, err
	}
	document := Document{PlatformVersion: version.CurrentPlatformVersion(), Reference: reference, Content: string(content)}
	if id == "agent-conversation" {
		contracts, err := agentconversation.SupportedContracts()
		if err != nil {
			return Document{}, err
		}
		known := contracts[0]
		document.Binding = &manifest.CapabilityBinding{BindingID: "agent", Contract: known.Pin}
		document.Methods = contractMethods(known)
	}
	return document, nil
}

func contractMethods(known capabilitycontract.KnownContract) []Method {
	methods := make([]Method, 0, len(known.Contract.Methods))
	for _, method := range known.Contract.Methods {
		methods = append(methods, Method{Declaration: manifest.MethodSpec{Method: method.Name,
			Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteCapability, BindingID: "agent", TargetMethod: method.Name}},
			Effect: method.Effect, RequiredPermissions: append([]string{}, method.RequiredPermissions...),
			ConfirmationRequired: method.Confirmation != nil && method.Confirmation.Mode == "required"})
	}
	return methods
}
