package capability

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/floegence/redevplugin/internal/jsonvalue"
	"github.com/floegence/redevplugin/pkg/capabilitycontract"
)

type Effect string

const (
	EffectRead    Effect = "read"
	EffectWrite   Effect = "write"
	EffectExecute Effect = "execute"
	EffectDelete  Effect = "delete"
	EffectAdmin   Effect = "admin"
)

var (
	ErrInvalidRegistration     = errors.New("capability registration is invalid")
	ErrRegistrationMissing     = errors.New("capability registration is missing")
	ErrInvalidExecutionBinding = errors.New("capability execution binding is invalid")
	ErrExecutionRevoked        = errors.New("capability execution is revoked")
	ErrInvalidExecutionFailure = errors.New("capability execution failure is invalid")
	ErrQuotaExceeded           = errors.New("capability execution quota exceeded")
)

type ExecutionFailureCode string

const (
	ExecutionFailureAdapterFailed   ExecutionFailureCode = "adapter_failed"
	ExecutionFailureContractInvalid ExecutionFailureCode = "contract_invalid"
	ExecutionFailurePlatformFailed  ExecutionFailureCode = "platform_failed"
	ExecutionFailureQuotaExceeded   ExecutionFailureCode = "quota_exceeded"
	ExecutionFailureRuntimeFailed   ExecutionFailureCode = "runtime_failed"

	ExecutionFailureMessage = "execution failed"
)

func (c ExecutionFailureCode) Valid() bool {
	switch c {
	case ExecutionFailureAdapterFailed,
		ExecutionFailureContractInvalid,
		ExecutionFailurePlatformFailed,
		ExecutionFailureQuotaExceeded,
		ExecutionFailureRuntimeFailed:
		return true
	default:
		return false
	}
}

type BusinessError struct {
	CapabilityID       string         `json:"capability_id,omitempty"`
	CapabilityVersion  string         `json:"capability_version,omitempty"`
	DetailSchemaSHA256 string         `json:"detail_schema_sha256,omitempty"`
	Code               string         `json:"code"`
	Message            string         `json:"message"`
	Details            map[string]any `json:"details,omitempty"`
}

func (e *BusinessError) Error() string {
	if e == nil || strings.TrimSpace(e.Message) == "" {
		return "host capability business error"
	}
	return e.Message
}

// NewBusinessError validates details against the closed canonical JSON set and
// retains a recursively cloned value. Callers may mutate their input after the
// function returns. Integers must be represented as safe json.Number or
// float64 values because native integer types are outside the cross-language
// execution contract.
func NewBusinessError(code, message string, details map[string]any) (*BusinessError, error) {
	ownedDetails, err := jsonvalue.CloneCanonicalMap(details)
	if err != nil {
		return nil, fmt.Errorf("create capability business error: %w", err)
	}
	return &BusinessError{Code: strings.TrimSpace(code), Message: strings.TrimSpace(message), Details: ownedDetails}, nil
}

type PluginIdentity struct {
	PublisherID       string `json:"publisher_id"`
	PluginID          string `json:"plugin_id"`
	PluginInstanceID  string `json:"plugin_instance_id"`
	PluginVersion     string `json:"plugin_version"`
	ActiveFingerprint string `json:"active_fingerprint"`
}

type SurfaceScope struct {
	SurfaceInstanceID    string `json:"surface_instance_id,omitempty"`
	OwnerSessionHash     string `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string `json:"owner_user_hash,omitempty"`
	OwnerEnvHash         string `json:"owner_env_hash,omitempty"`
	SessionChannelIDHash string `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID      string `json:"bridge_channel_id,omitempty"`
}

type PermissionEvidence struct {
	Required []string `json:"required"`
	Granted  []string `json:"granted"`
}

type ConfirmationEvidence struct {
	Required       bool   `json:"required"`
	Confirmed      bool   `json:"confirmed"`
	ConfirmationID string `json:"confirmation_id,omitempty"`
	RequestSHA256  string `json:"request_sha256,omitempty"`
	PlanSHA256     string `json:"plan_sha256,omitempty"`
	TargetSHA256   string `json:"target_sha256,omitempty"`
}

type RevisionEvidence struct {
	PolicyRevision     uint64 `json:"policy_revision"`
	ManagementRevision uint64 `json:"management_revision"`
	RevokeEpoch        uint64 `json:"revoke_epoch"`
}

type QuotaGrant struct {
	MaxConcurrent  int       `json:"max_concurrent,omitempty"`
	MaxDurationMS  int       `json:"max_duration_ms,omitempty"`
	MaxStreamBytes int64     `json:"max_stream_bytes,omitempty"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
}

type TargetDescriptor struct {
	Kind   string         `json:"kind"`
	Fields map[string]any `json:"fields"`
}

type RouteKind string

const (
	RouteCapability RouteKind = "capability"
	RouteWorker     RouteKind = "worker"
	RouteCoreAction RouteKind = "core_action"
)

type ExecutionBinding struct {
	InvocationID            string                  `json:"invocation_id"`
	AuditCorrelationID      string                  `json:"audit_correlation_id"`
	OperationID             string                  `json:"operation_id,omitempty"`
	StreamID                string                  `json:"stream_id,omitempty"`
	PublisherID             string                  `json:"publisher_id"`
	PluginID                string                  `json:"plugin_id"`
	PluginInstanceID        string                  `json:"plugin_instance_id"`
	PluginVersion           string                  `json:"plugin_version"`
	ActiveFingerprint       string                  `json:"active_fingerprint"`
	SurfaceInstanceID       string                  `json:"surface_instance_id,omitempty"`
	OwnerSessionHash        string                  `json:"owner_session_hash,omitempty"`
	OwnerUserHash           string                  `json:"owner_user_hash,omitempty"`
	OwnerEnvHash            string                  `json:"owner_env_hash,omitempty"`
	SessionChannelIDHash    string                  `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID         string                  `json:"bridge_channel_id,omitempty"`
	RouteKind               RouteKind               `json:"route_kind"`
	CapabilityID            string                  `json:"capability_id"`
	CapabilityVersion       string                  `json:"capability_version"`
	BindingID               string                  `json:"binding_id"`
	Contract                *capabilitycontract.Pin `json:"contract,omitempty"`
	Method                  string                  `json:"method"`
	TargetMethod            string                  `json:"target_method"`
	Effect                  Effect                  `json:"effect"`
	Execution               string                  `json:"execution"`
	Permissions             PermissionEvidence      `json:"permissions"`
	Confirmation            ConfirmationEvidence    `json:"confirmation"`
	Revision                RevisionEvidence        `json:"revision"`
	Quota                   QuotaGrant              `json:"quota"`
	Target                  TargetDescriptor        `json:"target"`
	TargetDescriptorSHA256  string                  `json:"target_descriptor_sha256"`
	StreamEventTypeName     string                  `json:"stream_event_type_name,omitempty"`
	StreamEventSchemaSHA256 string                  `json:"stream_event_schema_sha256,omitempty"`
}

// ExecutionOwnerScope is the exact short-lived session boundary for an
// operation or stream. Persistent resource ownership uses sessionctx.ResourceScope.
type ExecutionOwnerScope struct {
	OwnerSessionHash     string
	OwnerUserHash        string
	OwnerEnvHash         string
	SessionChannelIDHash string
}

func (s ExecutionOwnerScope) Valid() bool {
	return strings.TrimSpace(s.OwnerSessionHash) != "" &&
		strings.TrimSpace(s.OwnerUserHash) != "" &&
		strings.TrimSpace(s.OwnerEnvHash) != "" &&
		strings.TrimSpace(s.SessionChannelIDHash) != ""
}

func (s ExecutionOwnerScope) Normalized() ExecutionOwnerScope {
	s.OwnerSessionHash = strings.TrimSpace(s.OwnerSessionHash)
	s.OwnerUserHash = strings.TrimSpace(s.OwnerUserHash)
	s.OwnerEnvHash = strings.TrimSpace(s.OwnerEnvHash)
	s.SessionChannelIDHash = strings.TrimSpace(s.SessionChannelIDHash)
	return s
}

func (b ExecutionBinding) OwnerScope() ExecutionOwnerScope {
	return ExecutionOwnerScope{
		OwnerSessionHash:     b.OwnerSessionHash,
		OwnerUserHash:        b.OwnerUserHash,
		OwnerEnvHash:         b.OwnerEnvHash,
		SessionChannelIDHash: b.SessionChannelIDHash,
	}.Normalized()
}

func (b ExecutionBinding) Identity() PluginIdentity {
	return PluginIdentity{
		PublisherID:       b.PublisherID,
		PluginID:          b.PluginID,
		PluginInstanceID:  b.PluginInstanceID,
		PluginVersion:     b.PluginVersion,
		ActiveFingerprint: b.ActiveFingerprint,
	}
}

func (b ExecutionBinding) Surface() SurfaceScope {
	return SurfaceScope{
		SurfaceInstanceID:    b.SurfaceInstanceID,
		OwnerSessionHash:     b.OwnerSessionHash,
		OwnerUserHash:        b.OwnerUserHash,
		OwnerEnvHash:         b.OwnerEnvHash,
		SessionChannelIDHash: b.SessionChannelIDHash,
		BridgeChannelID:      b.BridgeChannelID,
	}
}

type ExecutionContext struct {
	ExecutionBinding
	Operation OperationSink `json:"-"`
	Stream    StreamSink    `json:"-"`
}

type Invocation struct {
	Execution ExecutionContext `json:"execution"`
	Arguments map[string]any   `json:"arguments,omitempty"`
}

type Result struct {
	Data any `json:"data,omitempty"`
}

type OperationSink interface {
	ID() string
	Complete(ctx context.Context) error
	Cancel(ctx context.Context, reason string) error
	Fail(ctx context.Context, code ExecutionFailureCode, cause error) error
	CancelRequested() <-chan struct{}
}

type StreamSink interface {
	ID() string
	Append(ctx context.Context, event any) error
	Close(ctx context.Context) error
	Fail(ctx context.Context, code ExecutionFailureCode, cause error) error
}

type StreamContract struct {
	EventTypeName string
	EventSchema   map[string]any
}

type TargetResolutionRequest struct {
	Identity          PluginIdentity         `json:"identity"`
	Surface           SurfaceScope           `json:"surface"`
	CapabilityID      string                 `json:"capability_id"`
	CapabilityVersion string                 `json:"capability_version"`
	BindingID         string                 `json:"binding_id"`
	Contract          capabilitycontract.Pin `json:"contract"`
	Method            string                 `json:"method"`
	TargetMethod      string                 `json:"target_method"`
	TargetInput       map[string]any         `json:"target_input"`
}

type OperationCancellation struct {
	Execution   ExecutionContext `json:"execution"`
	OperationID string           `json:"operation_id"`
	Reason      string           `json:"reason,omitempty"`
	RequestedAt time.Time        `json:"requested_at"`
}

type Adapter interface {
	Invoke(ctx context.Context, req Invocation) (Result, error)
}

type TargetProjector interface {
	ProjectTarget(ctx context.Context, req TargetResolutionRequest) (TargetDescriptor, error)
}

type OperationCanceler interface {
	CancelOperation(ctx context.Context, req OperationCancellation) error
}

type Registration struct {
	Contract        capabilitycontract.VerifiedContract
	TargetProjector TargetProjector
	Adapter         Adapter
}

type Registry struct {
	mu            sync.RWMutex
	registrations map[capabilitycontract.Pin]Registration
	contracts     *capabilitycontract.Registry
}

func NewRegistry() *Registry {
	return &Registry{
		registrations: map[capabilitycontract.Pin]Registration{},
		contracts:     capabilitycontract.NewRegistry(),
	}
}

func (r *Registry) Register(registration Registration) error {
	if r == nil {
		return fmt.Errorf("%w: registry is nil", ErrInvalidRegistration)
	}
	if registration.TargetProjector == nil {
		return fmt.Errorf("%w: target projector is required", ErrInvalidRegistration)
	}
	if registration.Adapter == nil {
		return fmt.Errorf("%w: adapter is required", ErrInvalidRegistration)
	}
	contract := registration.Contract.Contract
	if err := capabilitycontract.Validate(contract); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRegistration, err)
	}
	if contract.CapabilityID == "" || contract.CapabilityVersion == "" {
		return ErrInvalidRegistration
	}
	if err := r.AddContract(registration.Contract); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRegistration, err)
	}
	stored, err := r.RequireContract(registration.Contract.Pin)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRegistration, err)
	}
	registration.Contract = stored
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.registrations[registration.Contract.Pin]; ok &&
		(existing.Contract.Contract.CapabilityID != contract.CapabilityID || existing.Contract.Contract.CapabilityVersion != contract.CapabilityVersion) {
		return fmt.Errorf("%w: exact contract pin is already registered with another capability identity", ErrInvalidRegistration)
	}
	r.registrations[registration.Contract.Pin] = registration
	return nil
}

func (r *Registry) AddContract(contract capabilitycontract.VerifiedContract) error {
	if r == nil || r.contracts == nil {
		return fmt.Errorf("%w: registry is nil", ErrInvalidRegistration)
	}
	return r.contracts.Add(contract)
}

func (r *Registry) RequireContract(pin capabilitycontract.Pin) (capabilitycontract.VerifiedContract, error) {
	if r == nil || r.contracts == nil {
		return capabilitycontract.VerifiedContract{}, ErrRegistrationMissing
	}
	contract, err := r.contracts.Require(pin)
	if err != nil {
		return capabilitycontract.VerifiedContract{}, fmt.Errorf("%w: %v", ErrRegistrationMissing, err)
	}
	return contract, nil
}

func (r *Registry) Resolve(pin capabilitycontract.Pin) (Registration, error) {
	if r == nil {
		return Registration{}, ErrRegistrationMissing
	}
	if pin == (capabilitycontract.Pin{}) {
		return Registration{}, ErrRegistrationMissing
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	registration, ok := r.registrations[pin]
	if !ok {
		return Registration{}, ErrRegistrationMissing
	}
	contract, err := r.contracts.Require(registration.Contract.Pin)
	if err != nil {
		return Registration{}, fmt.Errorf("%w: %v", ErrRegistrationMissing, err)
	}
	registration.Contract = contract
	return registration, nil
}

// CloneTargetDescriptor validates and recursively clones target fields.
func CloneTargetDescriptor(target TargetDescriptor) (TargetDescriptor, error) {
	if !utf8.ValidString(target.Kind) {
		return TargetDescriptor{}, fmt.Errorf("%w: target kind is not valid UTF-8", ErrInvalidExecutionBinding)
	}
	fields, err := jsonvalue.CloneCanonicalMap(target.Fields)
	if err != nil {
		return TargetDescriptor{}, fmt.Errorf("%w: target fields: %v", ErrInvalidExecutionBinding, err)
	}
	target.Fields = fields
	return target, nil
}

// ValidateExecutionBinding validates the closed cross-language execution
// snapshot without invoking JSON marshalers or changing container ownership.
func ValidateExecutionBinding(binding ExecutionBinding) error {
	if err := validateExecutionBindingScalars(binding); err != nil {
		return err
	}
	if err := jsonvalue.ValidateCanonical(binding.Target.Fields); err != nil {
		return fmt.Errorf("%w: target fields: %v", ErrInvalidExecutionBinding, err)
	}
	return nil
}

// CloneExecutionBinding returns an independently owned execution snapshot.
func CloneExecutionBinding(binding ExecutionBinding) (ExecutionBinding, error) {
	if err := validateExecutionBindingScalars(binding); err != nil {
		return ExecutionBinding{}, err
	}
	target, err := CloneTargetDescriptor(binding.Target)
	if err != nil {
		return ExecutionBinding{}, err
	}
	binding.Target = target
	if binding.Contract != nil {
		contract := *binding.Contract
		binding.Contract = &contract
	}
	if binding.Permissions.Required != nil {
		binding.Permissions.Required = append([]string{}, binding.Permissions.Required...)
	}
	if binding.Permissions.Granted != nil {
		binding.Permissions.Granted = append([]string{}, binding.Permissions.Granted...)
	}
	return binding, nil
}

func validateExecutionBindingScalars(binding ExecutionBinding) error {
	if binding.RouteKind != "" && !validExecutionRouteKind(binding.RouteKind) {
		return fmt.Errorf("%w: route_kind %q is invalid", ErrInvalidExecutionBinding, binding.RouteKind)
	}
	if binding.Effect != "" && !validExecutionEffect(binding.Effect) {
		return fmt.Errorf("%w: effect %q is invalid", ErrInvalidExecutionBinding, binding.Effect)
	}
	if binding.Execution != "" && !validExecutionMode(binding.Execution) {
		return fmt.Errorf("%w: execution %q is invalid", ErrInvalidExecutionBinding, binding.Execution)
	}
	if !jsonvalue.IsSafeUnsignedInteger(binding.Revision.PolicyRevision) ||
		!jsonvalue.IsSafeUnsignedInteger(binding.Revision.ManagementRevision) ||
		!jsonvalue.IsSafeUnsignedInteger(binding.Revision.RevokeEpoch) {
		return fmt.Errorf("%w: revision exceeds the JSON safe integer range", ErrInvalidExecutionBinding)
	}
	if !safeNonnegativeInt(binding.Quota.MaxConcurrent) ||
		!safeNonnegativeInt(binding.Quota.MaxDurationMS) ||
		!safeNonnegativeInt64(binding.Quota.MaxStreamBytes) {
		return fmt.Errorf("%w: quota is outside the JSON safe integer range", ErrInvalidExecutionBinding)
	}
	if !binding.Quota.ExpiresAt.IsZero() {
		year := binding.Quota.ExpiresAt.Year()
		if year < 0 || year > 9999 || binding.Quota.ExpiresAt != binding.Quota.ExpiresAt.UTC().Round(0) {
			return fmt.Errorf("%w: quota expiry must be a canonical UTC RFC3339 value", ErrInvalidExecutionBinding)
		}
	}
	if binding.Contract != nil {
		if err := capabilitycontract.ValidatePin(*binding.Contract); err != nil {
			return fmt.Errorf("%w: contract pin: %v", ErrInvalidExecutionBinding, err)
		}
	}
	if err := validateExecutionBindingStrings(binding); err != nil {
		return err
	}
	return nil
}

func validExecutionRouteKind(kind RouteKind) bool {
	switch kind {
	case RouteCapability, RouteWorker, RouteCoreAction:
		return true
	default:
		return false
	}
}

func validExecutionEffect(effect Effect) bool {
	switch effect {
	case EffectRead, EffectWrite, EffectExecute, EffectDelete, EffectAdmin:
		return true
	default:
		return false
	}
}

func validExecutionMode(mode string) bool {
	switch mode {
	case "sync", "operation", "subscription":
		return true
	default:
		return false
	}
}

func safeNonnegativeInt(value int) bool {
	return value >= 0 && uint64(value) <= jsonvalue.MaxSafeInteger
}

func safeNonnegativeInt64(value int64) bool {
	return value >= 0 && uint64(value) <= jsonvalue.MaxSafeInteger
}

func validateExecutionBindingStrings(binding ExecutionBinding) error {
	if !validUTF8Strings(
		binding.InvocationID, binding.AuditCorrelationID, binding.OperationID, binding.StreamID,
		binding.PublisherID, binding.PluginID, binding.PluginInstanceID, binding.PluginVersion,
		binding.ActiveFingerprint, binding.SurfaceInstanceID, binding.OwnerSessionHash,
		binding.OwnerUserHash, binding.OwnerEnvHash, binding.SessionChannelIDHash,
		binding.BridgeChannelID, binding.CapabilityID, binding.CapabilityVersion,
		binding.BindingID, binding.Method, binding.TargetMethod, binding.Target.Kind,
		binding.TargetDescriptorSHA256, binding.StreamEventTypeName, binding.StreamEventSchemaSHA256,
		binding.Confirmation.ConfirmationID, binding.Confirmation.RequestSHA256,
		binding.Confirmation.PlanSHA256, binding.Confirmation.TargetSHA256,
	) {
		return fmt.Errorf("%w: string field is not valid UTF-8", ErrInvalidExecutionBinding)
	}
	if binding.Contract != nil {
		pin := binding.Contract
		if !validUTF8Strings(
			pin.PublisherID, pin.ContractID, pin.ContractVersion, pin.ArtifactRef, pin.ArtifactSHA256,
			pin.ManifestRef, pin.ManifestSHA256, pin.SignatureRef, pin.SignatureSHA256,
			pin.SignatureKeyID, pin.SignaturePolicyEpoch, pin.SignatureRevocationEpoch,
			pin.CompatibilityRef, pin.CompatibilitySHA256, pin.GeneratedClientRef,
			pin.GeneratedClientSHA256, pin.NoticesRef, pin.NoticesSHA256,
		) {
			return fmt.Errorf("%w: contract string field is not valid UTF-8", ErrInvalidExecutionBinding)
		}
	}
	for _, values := range [][]string{binding.Permissions.Required, binding.Permissions.Granted} {
		for _, value := range values {
			if !utf8.ValidString(value) {
				return fmt.Errorf("%w: permission is not valid UTF-8", ErrInvalidExecutionBinding)
			}
		}
	}
	return nil
}

func validUTF8Strings(values ...string) bool {
	for _, value := range values {
		if !utf8.ValidString(value) {
			return false
		}
	}
	return true
}
