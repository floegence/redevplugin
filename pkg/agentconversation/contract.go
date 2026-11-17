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

//go:embed contract.v1.gen.json
var contractV1Artifact []byte

func Contract() (capabilitycontract.KnownContract, error) {
	return capabilitycontract.NewKnownContractFromArtifact(contractArtifact)
}

// SupportedContracts includes the exact immutable 3.30 artifact. Hosts register
// each with the same adapter so installed 1.0 clients keep their original pin.
// New authors use Contract, which includes explicit component connectors.
func SupportedContracts() ([]capabilitycontract.KnownContract, error) {
	contracts := make([]capabilitycontract.KnownContract, 0, 2)
	for _, artifact := range [][]byte{contractArtifact, contractV1Artifact} {
		known, err := capabilitycontract.NewKnownContractFromArtifact(artifact)
		if err != nil {
			return nil, err
		}
		contracts = append(contracts, known)
	}
	return contracts, nil
}
