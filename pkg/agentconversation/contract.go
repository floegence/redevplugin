// Package agentconversation publishes the scoped Agent conversation capability.
// Hosts own Agent execution, canonical history and business-object lifecycles;
// the platform owns invocation authority, confirmation, streams and the SDK.
package agentconversation

import (
	_ "embed"

	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
)

//go:generate go run ../../internal/agentcontractgenerate

//go:embed contract.gen.json
var contractArtifact []byte

func Contract() (capabilitycontract.KnownContract, error) {
	return capabilitycontract.NewKnownContractFromArtifact(contractArtifact)
}
