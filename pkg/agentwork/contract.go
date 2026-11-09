// Package agentwork publishes a host-neutral Agent work contract through the
// existing capability bridge. Hosts own the Agent engine and business binding.
package agentwork

import (
	_ "embed"
	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
)

//go:generate go run ./internal/generate

//go:embed contract.gen.json
var contractArtifact []byte

// Contract binds registration to the exact published artifact. Work references
// are resolved under the platform-verified plugin and environment identity.
func Contract() (capabilitycontract.KnownContract, error) {
	return capabilitycontract.NewKnownContractFromArtifact(contractArtifact)
}
