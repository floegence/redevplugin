package capabilitycontract

import (
	"fmt"
	"strings"
	"sync"

	"golang.org/x/mod/semver"
)

type Registry struct {
	mu      sync.RWMutex
	records map[string]VerifiedContract
}

func NewRegistry() *Registry {
	return &Registry{records: map[string]VerifiedContract{}}
}

func (r *Registry) Add(contract VerifiedContract) error {
	if r == nil {
		return fmt.Errorf("%w: registry is nil", ErrInvalidBundle)
	}
	if err := validatePin(contract.Pin); err != nil {
		return err
	}
	if err := Validate(contract.Contract); err != nil {
		return err
	}
	if !contract.authentic() {
		return fmt.Errorf("%w: contract was not produced by artifact verification", ErrSignature)
	}
	if contract.Contract.PublisherID != contract.Pin.PublisherID || contract.Contract.ContractID != contract.Pin.ContractID ||
		contract.Contract.ContractVersion != contract.Pin.ContractVersion {
		return fmt.Errorf("%w: verified contract identity mismatch", ErrPinMismatch)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := pinKey(contract.Pin)
	if existing, ok := r.records[key]; ok && existing.Pin != contract.Pin {
		return fmt.Errorf("%w: contract identity is already registered with another pin", ErrPinMismatch)
	}
	r.records[key] = cloneVerifiedContract(contract)
	return nil
}

func (r *Registry) Require(pin Pin) (VerifiedContract, error) {
	if r == nil {
		return VerifiedContract{}, fmt.Errorf("%w: registry is nil", ErrInvalidBundle)
	}
	if err := validatePin(pin); err != nil {
		return VerifiedContract{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, ok := r.records[pinKey(pin)]
	if !ok || record.Pin != pin {
		return VerifiedContract{}, fmt.Errorf("%w: verified contract is not registered", ErrPinMismatch)
	}
	return cloneVerifiedContract(record), nil
}

func (r *Registry) ResolveCapability(capabilityID, minimumVersion string) (VerifiedContract, error) {
	if r == nil {
		return VerifiedContract{}, fmt.Errorf("%w: registry is nil", ErrInvalidBundle)
	}
	capabilityID = strings.TrimSpace(capabilityID)
	minimumSemver, err := normalizedCapabilitySemver(minimumVersion)
	if capabilityID == "" || err != nil {
		return VerifiedContract{}, fmt.Errorf("%w: capability identity or minimum version is invalid", ErrPinMismatch)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var matched *VerifiedContract
	for _, record := range r.records {
		if record.Contract.CapabilityID != capabilityID {
			continue
		}
		candidateSemver, candidateErr := normalizedCapabilitySemver(record.Contract.CapabilityVersion)
		if candidateErr != nil || semver.Compare(candidateSemver, minimumSemver) < 0 {
			continue
		}
		if matched != nil {
			matchedSemver, _ := normalizedCapabilitySemver(matched.Contract.CapabilityVersion)
			comparison := semver.Compare(candidateSemver, matchedSemver)
			if comparison == 0 && record.Pin != matched.Pin {
				return VerifiedContract{}, fmt.Errorf("%w: capability resolves to multiple contracts with equal semver precedence", ErrPinMismatch)
			}
			if comparison <= 0 {
				continue
			}
		}
		copy := cloneVerifiedContract(record)
		matched = &copy
	}
	if matched == nil {
		return VerifiedContract{}, fmt.Errorf("%w: verified capability contract is not registered", ErrPinMismatch)
	}
	return *matched, nil
}

func CompareCapabilityVersions(left, right string) (int, error) {
	leftSemver, err := normalizedCapabilitySemver(left)
	if err != nil {
		return 0, err
	}
	rightSemver, err := normalizedCapabilitySemver(right)
	if err != nil {
		return 0, err
	}
	return semver.Compare(leftSemver, rightSemver), nil
}

func normalizedCapabilitySemver(value string) (string, error) {
	normalized, ok := normalizeSemver(value)
	if !ok {
		return "", fmt.Errorf("%w: capability version is invalid", ErrInvalidContract)
	}
	return normalized, nil
}

func normalizeSemver(value string) (string, bool) {
	if value == "" || strings.TrimSpace(value) != value || strings.HasPrefix(value, "v") {
		return "", false
	}
	normalized := "v" + value
	return normalized, semver.IsValid(normalized)
}

func pinKey(pin Pin) string {
	return pin.PublisherID + "\x00" + pin.ContractID + "\x00" + pin.ContractVersion
}

func cloneVerifiedContract(contract VerifiedContract) VerifiedContract {
	methods := make([]Method, len(contract.Contract.Methods))
	for index, method := range contract.Contract.Methods {
		methods[index] = method
		methods[index].RequiredPermissions = append([]string(nil), method.RequiredPermissions...)
		methods[index].TargetFields = append([]string(nil), method.TargetFields...)
		methods[index].TargetSchema = cloneJSONMap(method.TargetSchema)
		methods[index].RequestSchema = cloneJSONMap(method.RequestSchema)
		methods[index].ResponseSchema = cloneJSONMap(method.ResponseSchema)
		methods[index].EventSchema = cloneJSONMap(method.EventSchema)
		if method.Confirmation != nil {
			confirmation := *method.Confirmation
			confirmation.RequestHashFields = append([]string(nil), method.Confirmation.RequestHashFields...)
			methods[index].Confirmation = &confirmation
		}
		if method.CancelPolicy != nil {
			cancelPolicy := *method.CancelPolicy
			methods[index].CancelPolicy = &cancelPolicy
		}
	}
	contract.Contract.Methods = methods
	errors := make([]BusinessError, len(contract.Contract.Errors))
	for index, businessError := range contract.Contract.Errors {
		errors[index] = businessError
		errors[index].DetailsSchema = cloneJSONMap(businessError.DetailsSchema)
	}
	contract.Contract.Errors = errors
	contract.Manifest.Entries = append([]ManifestEntry(nil), contract.Manifest.Entries...)
	contract.GeneratedClient = append([]byte(nil), contract.GeneratedClient...)
	contract.Notices = append([]Notice(nil), contract.Notices...)
	return contract
}

func (v *VerifiedContract) seal() error {
	digest, err := verifiedContractDigest(*v)
	if err != nil {
		return err
	}
	v.verificationSeal = digest
	return nil
}

func (v VerifiedContract) authentic() bool {
	if v.verificationSeal == "" || v.publicKeySHA256 == "" {
		return false
	}
	digest, err := verifiedContractDigest(v)
	return err == nil && digest == v.verificationSeal
}

func verifiedContractDigest(contract VerifiedContract) (string, error) {
	payload := struct {
		Contract        Contract      `json:"contract"`
		Pin             Pin           `json:"pin"`
		Manifest        Manifest      `json:"manifest"`
		Compatibility   Compatibility `json:"compatibility"`
		GeneratedClient []byte        `json:"generated_client"`
		Notices         []Notice      `json:"notices"`
		PublicKeySHA256 string        `json:"public_key_sha256"`
	}{
		Contract:        contract.Contract,
		Pin:             contract.Pin,
		Manifest:        contract.Manifest,
		Compatibility:   contract.Compatibility,
		GeneratedClient: contract.GeneratedClient,
		Notices:         contract.Notices,
		PublicKeySHA256: contract.publicKeySHA256,
	}
	raw, err := canonicalJSON(payload)
	if err != nil {
		return "", err
	}
	return sha256Hex(raw), nil
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
