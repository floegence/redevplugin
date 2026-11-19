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

//go:embed contract.v11.gen.json
var contractV11Artifact []byte

//go:embed contract.v12.gen.json
var contractV12Artifact []byte

//go:embed contract.v13.gen.json
var contractV13Artifact []byte

func Contract() (capabilitycontract.KnownContract, error) {
	return capabilitycontract.NewKnownContractFromArtifact(contractArtifact)
}

// SupportedContracts includes all immutable released pins. Hosts register each
// with the same adapter; new authors use Contract.
func SupportedContracts() ([]capabilitycontract.KnownContract, error) {
	contracts := make([]capabilitycontract.KnownContract, 0, 5)
	for _, artifact := range [][]byte{contractArtifact, contractV13Artifact, contractV12Artifact, contractV11Artifact, contractV1Artifact} {
		known, err := capabilitycontract.NewKnownContractFromArtifact(artifact)
		if err != nil {
			return nil, err
		}
		contracts = append(contracts, known)
	}
	return contracts, nil
}
