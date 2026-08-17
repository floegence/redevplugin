package capabilitycontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"

	platformversion "github.com/floegence/redevplugin/v3/pkg/version"
)

var sha256HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Registry struct {
	mu      sync.RWMutex
	records map[string]KnownContract
}

func NewRegistry() *Registry {
	return &Registry{records: map[string]KnownContract{}}
}

// NewKnownContract validates a Host-owned contract and binds its local
// registry identity to the canonical contract bytes shipped with the Host.
func NewKnownContract(contract Contract) (KnownContract, error) {
	if err := Validate(contract); err != nil {
		return KnownContract{}, err
	}
	digest, err := contractSHA256(contract)
	if err != nil {
		return KnownContract{}, fmt.Errorf("%w: hash contract: %v", ErrInvalidContract, err)
	}
	return newKnownContract(contract, digest, digest), nil
}

// NewKnownContractFromArtifact validates a published contract artifact while
// retaining the digest of its exact immutable bytes as the registry pin.
func NewKnownContractFromArtifact(raw []byte) (KnownContract, error) {
	var contract Contract
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		return KnownContract{}, fmt.Errorf("%w: decode contract artifact: %v", ErrInvalidContract, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return KnownContract{}, fmt.Errorf("%w: contract artifact contains a trailing value", ErrInvalidContract)
		}
		return KnownContract{}, fmt.Errorf("%w: decode contract artifact trailer: %v", ErrInvalidContract, err)
	}
	if err := Validate(contract); err != nil {
		return KnownContract{}, err
	}
	contractDigest, err := contractSHA256(contract)
	if err != nil {
		return KnownContract{}, fmt.Errorf("%w: hash contract: %v", ErrInvalidContract, err)
	}
	artifactDigest := sha256.Sum256(raw)
	return newKnownContract(contract, contractDigest, hex.EncodeToString(artifactDigest[:])), nil
}

func newKnownContract(contract Contract, contractDigest, artifactDigest string) KnownContract {
	known := KnownContract{
		Contract: cloneContract(contract),
		Pin: Pin{
			PublisherID:     contract.PublisherID,
			ContractID:      contract.ContractID,
			ContractVersion: contract.ContractVersion,
			ArtifactSHA256:  artifactDigest,
		},
	}
	known.seal = contractDigest
	known.artifactSeal = artifactDigest
	return known
}

func (r *Registry) Add(contract KnownContract) error {
	if r == nil {
		return fmt.Errorf("%w: registry is nil", ErrInvalidContract)
	}
	if err := validateKnownContract(contract); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := pinKey(contract.Pin)
	if existing, ok := r.records[key]; ok && existing.Pin != contract.Pin {
		return fmt.Errorf("%w: contract identity is already registered with another hash", ErrIdentityMismatch)
	}
	r.records[key] = cloneKnownContract(contract)
	return nil
}

func (r *Registry) Require(pin Pin) (KnownContract, error) {
	if r == nil {
		return KnownContract{}, fmt.Errorf("%w: registry is nil", ErrInvalidContract)
	}
	if err := ValidatePin(pin); err != nil {
		return KnownContract{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, ok := r.records[pinKey(pin)]
	if !ok || record.Pin != pin {
		return KnownContract{}, fmt.Errorf("%w: known contract is not registered", ErrIdentityMismatch)
	}
	if err := validateKnownContract(record); err != nil {
		return KnownContract{}, err
	}
	return cloneKnownContract(record), nil
}

func ValidatePin(pin Pin) error {
	for name, value := range map[string]string{
		"publisher_id": pin.PublisherID,
		"contract_id":  pin.ContractID,
	} {
		if !idPattern.MatchString(value) || strings.TrimSpace(value) != value {
			return fmt.Errorf("%w: %s is invalid", ErrIdentityMismatch, name)
		}
	}
	if _, err := platformversion.ParseSemVer(pin.ContractVersion); err != nil {
		return fmt.Errorf("%w: contract_version is invalid", ErrIdentityMismatch)
	}
	if !sha256HexPattern.MatchString(pin.ArtifactSHA256) {
		return fmt.Errorf("%w: artifact_sha256 is invalid", ErrIdentityMismatch)
	}
	return nil
}

func validateKnownContract(known KnownContract) error {
	if err := ValidatePin(known.Pin); err != nil {
		return err
	}
	if err := Validate(known.Contract); err != nil {
		return err
	}
	digest, err := contractSHA256(known.Contract)
	if err != nil {
		return fmt.Errorf("%w: hash contract: %v", ErrInvalidContract, err)
	}
	if known.Contract.PublisherID != known.Pin.PublisherID ||
		known.Contract.ContractID != known.Pin.ContractID ||
		known.Contract.ContractVersion != known.Pin.ContractVersion ||
		known.seal != digest || known.Pin.ArtifactSHA256 != known.artifactSeal {
		return ErrIdentityMismatch
	}
	return nil
}

func contractSHA256(contract Contract) (string, error) {
	raw, err := json.Marshal(contract)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func pinKey(pin Pin) string {
	return pin.PublisherID + "\x00" + pin.ContractID + "\x00" + pin.ContractVersion
}

func cloneKnownContract(contract KnownContract) KnownContract {
	contract.Contract = cloneContract(contract.Contract)
	return contract
}

func cloneContract(contract Contract) Contract {
	methods := make([]Method, len(contract.Methods))
	for index, method := range contract.Methods {
		methods[index] = method
		methods[index].RequiredPermissions = cloneStrings(method.RequiredPermissions)
		methods[index].TargetFields = cloneStrings(method.TargetFields)
		methods[index].TargetSchema = cloneJSONMap(method.TargetSchema)
		methods[index].RequestSchema = cloneJSONMap(method.RequestSchema)
		methods[index].ResponseSchema = cloneJSONMap(method.ResponseSchema)
		methods[index].EventSchema = cloneJSONMap(method.EventSchema)
		if method.Confirmation != nil {
			confirmation := *method.Confirmation
			confirmation.RequestHashFields = cloneStrings(method.Confirmation.RequestHashFields)
			methods[index].Confirmation = &confirmation
		}
		if method.CancelPolicy != nil {
			cancelPolicy := *method.CancelPolicy
			methods[index].CancelPolicy = &cancelPolicy
		}
	}
	contract.Methods = methods
	errors := make([]BusinessError, len(contract.Errors))
	for index, businessError := range contract.Errors {
		errors[index] = businessError
		errors[index].DetailsSchema = cloneJSONMap(businessError.DetailsSchema)
	}
	contract.Errors = errors
	return contract
}

func cloneStrings(value []string) []string {
	if value == nil {
		return nil
	}
	return append([]string{}, value...)
}

func cloneJSONMap(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	cloned := make(map[string]any, len(value))
	for key, item := range value {
		cloned[key] = cloneJSONValue(item)
	}
	return cloned
}

func cloneJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneJSONMap(typed)
	case []any:
		cloned := make([]any, len(typed))
		for index, item := range typed {
			cloned[index] = cloneJSONValue(item)
		}
		return cloned
	case []string:
		return append([]string(nil), typed...)
	default:
		return typed
	}
}
