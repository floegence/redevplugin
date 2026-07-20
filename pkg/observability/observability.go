package observability

import (
	"context"
	"errors"
	"math"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"
)

const (
	defaultListLimit = 100
	maxListLimit     = 1000
	defaultMaxEvents = 4096
)

var (
	ErrInvalidEvent              = errors.New("plugin observability event is invalid")
	ErrInvalidAuditDetails       = errors.New("plugin audit details are invalid")
	ErrInvalidDiagnosticSeverity = errors.New("plugin diagnostic severity is invalid")
	ErrInvalidDiagnosticMessage  = errors.New("plugin diagnostic message is invalid")
	ErrInvalidDiagnosticDetails  = errors.New("plugin diagnostic details are invalid")
	ErrInvalidDiagnosticFailure  = errors.New("plugin diagnostic failure is invalid")
	ErrDiagnosticScopeRequired   = errors.New("complete diagnostic owner scope is required")
)

const maxSafeInteger = uint64(1<<53 - 1)

var (
	stableValuePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)
	stableCodePattern  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
)

type DiagnosticSeverity string

const (
	DiagnosticSeverityInfo    DiagnosticSeverity = "info"
	DiagnosticSeverityWarning DiagnosticSeverity = "warning"
)

func (severity DiagnosticSeverity) Valid() bool {
	return severity == DiagnosticSeverityInfo || severity == DiagnosticSeverityWarning
}

type FailureCode string

const (
	FailureAdapter FailureCode = "adapter_failure"
	FailureOwner   FailureCode = "owner_failure"
	FailureScope   FailureCode = "scope_failure"
	FailureAction  FailureCode = "action_failure"
)

func (code FailureCode) Valid() bool {
	switch code {
	case FailureAdapter, FailureOwner, FailureScope, FailureAction:
		return true
	default:
		return false
	}
}

type RuntimeProcessFailureCode string

const (
	RuntimeProcessFailed                      RuntimeProcessFailureCode = "RUNTIME_PROCESS_FAILED"
	RuntimeProcessExitUnexpected              RuntimeProcessFailureCode = "RUNTIME_PROCESS_EXIT_UNEXPECTED"
	RuntimeProcessExitUnrecognized            RuntimeProcessFailureCode = "RUNTIME_PROCESS_EXIT_UNRECOGNIZED"
	RuntimeProcessSignalled                   RuntimeProcessFailureCode = "RUNTIME_PROCESS_SIGNALLED"
	RuntimeProcessWriterCapacityOverflow      RuntimeProcessFailureCode = "IPC_WRITER_CAPACITY_OVERFLOW"
	RuntimeProcessWriterCapacityLimitExceeded RuntimeProcessFailureCode = "IPC_WRITER_CAPACITY_LIMIT_EXCEEDED"
	RuntimeProcessWriterStartFailed           RuntimeProcessFailureCode = "IPC_WRITER_START_FAILED"
	RuntimeProcessWriterClosed                RuntimeProcessFailureCode = "IPC_WRITER_CLOSED"
	RuntimeProcessWriterBatchSizeOverflow     RuntimeProcessFailureCode = "IPC_WRITER_BATCH_SIZE_OVERFLOW"
	RuntimeProcessWriterWriteFailed           RuntimeProcessFailureCode = "IPC_WRITER_WRITE_FAILED"
	RuntimeProcessWriterFlushFailed           RuntimeProcessFailureCode = "IPC_WRITER_FLUSH_FAILED"
	RuntimeProcessWriterPanicked              RuntimeProcessFailureCode = "IPC_WRITER_PANICKED"
)

var runtimeProcessFailureCodes = [...]RuntimeProcessFailureCode{
	RuntimeProcessFailed,
	RuntimeProcessExitUnexpected,
	RuntimeProcessExitUnrecognized,
	RuntimeProcessSignalled,
	RuntimeProcessWriterCapacityOverflow,
	RuntimeProcessWriterCapacityLimitExceeded,
	RuntimeProcessWriterStartFailed,
	RuntimeProcessWriterClosed,
	RuntimeProcessWriterBatchSizeOverflow,
	RuntimeProcessWriterWriteFailed,
	RuntimeProcessWriterFlushFailed,
	RuntimeProcessWriterPanicked,
}

func (code RuntimeProcessFailureCode) Valid() bool {
	for _, allowed := range runtimeProcessFailureCodes {
		if code == allowed {
			return true
		}
	}
	return false
}

// RuntimeProcessFailureCodes returns an owned copy of the released diagnostic code set.
func RuntimeProcessFailureCodes() []RuntimeProcessFailureCode {
	return append([]RuntimeProcessFailureCode(nil), runtimeProcessFailureCodes[:]...)
}

type FailureComponent string

const (
	FailureComponentExecution FailureComponent = "execution"
	FailureComponentHTTP      FailureComponent = "http"
	FailureComponentLifecycle FailureComponent = "lifecycle"
	FailureComponentRuntime   FailureComponent = "runtime"
	FailureComponentSecrets   FailureComponent = "secrets"
	FailureComponentSecurity  FailureComponent = "security"
)

func (component FailureComponent) Valid() bool {
	switch component {
	case FailureComponentExecution, FailureComponentHTTP, FailureComponentLifecycle,
		FailureComponentRuntime, FailureComponentSecrets, FailureComponentSecurity:
		return true
	default:
		return false
	}
}

type FailureOperation string

const (
	FailureOperationExecutionRetentionPrune  FailureOperation = "execution.retention_prune"
	FailureOperationExecutionFail            FailureOperation = "execution.fail"
	FailureOperationExecutionDurationPersist FailureOperation = "execution.duration_persist"
	FailureOperationHTTPAdapter              FailureOperation = "http.adapter"
	FailureOperationLifecycle                FailureOperation = "lifecycle.operation"
	FailureOperationRuntimeStop              FailureOperation = "runtime.stop"
	FailureOperationRuntimeRevoke            FailureOperation = "runtime.revoke"
	FailureOperationRuntimeProcessStop       FailureOperation = "runtime.process.stop"
	FailureOperationRuntimeProcessExit       FailureOperation = "runtime.process.exit"
	FailureOperationRuntimeProcessOutput     FailureOperation = "runtime.process.output"
	FailureOperationRuntimeHostcall          FailureOperation = "runtime.hostcall"
	FailureOperationRuntimeIPCInvalidate     FailureOperation = "runtime.ipc.invalidate"
	FailureOperationSecretsAdapter           FailureOperation = "secrets.adapter"
	FailureOperationSecurityEventPersist     FailureOperation = "security_event.persist"
	FailureOperationSecurityMutationComplete FailureOperation = "security_mutation.complete"
	FailureOperationSecurityAuditExport      FailureOperation = "security_audit.export"
	FailureOperationMethodReject             FailureOperation = "method.reject"
)

func (operation FailureOperation) Valid() bool {
	switch operation {
	case FailureOperationExecutionRetentionPrune, FailureOperationExecutionFail,
		FailureOperationExecutionDurationPersist, FailureOperationHTTPAdapter,
		FailureOperationLifecycle, FailureOperationRuntimeStop, FailureOperationRuntimeRevoke,
		FailureOperationRuntimeProcessStop, FailureOperationRuntimeProcessExit,
		FailureOperationRuntimeProcessOutput, FailureOperationRuntimeHostcall,
		FailureOperationRuntimeIPCInvalidate, FailureOperationSecretsAdapter,
		FailureOperationSecurityEventPersist, FailureOperationSecurityMutationComplete,
		FailureOperationSecurityAuditExport, FailureOperationMethodReject:
		return true
	default:
		return false
	}
}

// Failure is a stable diagnostic description that intentionally excludes the
// underlying error text. It is safe to persist at adapter and action boundaries.
type Failure struct {
	Code      FailureCode      `json:"code"`
	Component FailureComponent `json:"component"`
	Operation FailureOperation `json:"operation"`
}

func FailureFromError(code FailureCode, component FailureComponent, operation FailureOperation, cause error) Failure {
	if cause == nil {
		return Failure{}
	}
	return Failure{Code: code, Component: component, Operation: operation}
}

func (f Failure) Valid() bool {
	return f.Code.Valid() && f.Component.Valid() && f.Operation.Valid()
}

func (f Failure) Empty() bool { return f == (Failure{}) }

func (f Failure) Error() string {
	if !f.Valid() {
		return "invalid_diagnostic_failure"
	}
	return string(f.Code) + ": " + string(f.Component) + "." + string(f.Operation)
}

type DiagnosticDetails struct {
	OperationsDeleted         int64                     `json:"operations_deleted,omitempty"`
	StreamsDeleted            int64                     `json:"streams_deleted,omitempty"`
	InvocationID              string                    `json:"invocation_id,omitempty"`
	Method                    string                    `json:"method,omitempty"`
	FailureCode               string                    `json:"failure_code,omitempty"`
	RuntimeProcessFailureCode RuntimeProcessFailureCode `json:"runtime_process_failure_code,omitempty"`
	OperationID               string                    `json:"operation_id,omitempty"`
	StreamID                  string                    `json:"stream_id,omitempty"`
	RuntimeInstanceID         string                    `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID       string                    `json:"runtime_generation_id,omitempty"`
	RuntimeVersion            string                    `json:"runtime_version,omitempty"`
	RustIPCVersion            string                    `json:"rust_ipc_version,omitempty"`
	WASMABIVersion            string                    `json:"wasm_abi_version,omitempty"`
	RuntimeTargetOS           string                    `json:"runtime_target_os,omitempty"`
	RuntimeTargetArch         string                    `json:"runtime_target_arch,omitempty"`
	RuntimeArtifactSHA256     string                    `json:"runtime_artifact_sha256,omitempty"`
	OS                        string                    `json:"os,omitempty"`
	Arch                      string                    `json:"arch,omitempty"`
	Stream                    string                    `json:"stream,omitempty"`
	PackageHash               string                    `json:"package_hash,omitempty"`
	Artifact                  string                    `json:"artifact,omitempty"`
	PluginInstanceID          string                    `json:"plugin_instance_id,omitempty"`
	StoreID                   string                    `json:"store_id,omitempty"`
	Operation                 string                    `json:"operation,omitempty"`
	Hostcall                  string                    `json:"hostcall,omitempty"`
	Code                      string                    `json:"code,omitempty"`
	ConnectorID               string                    `json:"connector_id,omitempty"`
	Transport                 string                    `json:"transport,omitempty"`
	RevokeEpoch               uint64                    `json:"revoke_epoch,omitempty"`
	StageID                   string                    `json:"stage_id,omitempty"`
	Reason                    string                    `json:"reason,omitempty"`
	SurfaceInstanceID         string                    `json:"surface_instance_id,omitempty"`
}

func (details DiagnosticDetails) Valid() bool {
	if details.OperationsDeleted < 0 || uint64(details.OperationsDeleted) > maxSafeInteger ||
		details.StreamsDeleted < 0 || uint64(details.StreamsDeleted) > maxSafeInteger ||
		details.RevokeEpoch > maxSafeInteger {
		return false
	}
	for _, value := range []string{
		details.InvocationID, details.Method, details.FailureCode, details.OperationID, details.StreamID,
		details.RuntimeInstanceID, details.RuntimeGenerationID, details.RuntimeVersion, details.RustIPCVersion,
		details.WASMABIVersion, details.RuntimeTargetOS, details.RuntimeTargetArch, details.RuntimeArtifactSHA256,
		details.OS, details.Arch, details.Stream, details.PackageHash, details.PluginInstanceID, details.StoreID,
		details.Operation, details.Hostcall, details.ConnectorID, details.Transport, details.StageID, details.Reason,
		details.SurfaceInstanceID,
	} {
		if value != "" && !validStableValue(value) {
			return false
		}
	}
	if details.Code != "" && !stableCodePattern.MatchString(details.Code) {
		return false
	}
	if details.RuntimeProcessFailureCode != "" && !details.RuntimeProcessFailureCode.Valid() {
		return false
	}
	return details.Artifact == "" || validPackageRelativePath(details.Artifact)
}

type AuditSink interface {
	AppendPluginAudit(ctx context.Context, event AuditEvent) error
}

type DiagnosticsSink interface {
	AppendPluginDiagnostic(ctx context.Context, event DiagnosticEvent) error
}

type DiagnosticLister interface {
	ListPluginDiagnostics(ctx context.Context, req ListDiagnosticRequest) ([]DiagnosticEvent, error)
}

type AuditEvent struct {
	EventID           string         `json:"event_id,omitempty"`
	Type              string         `json:"type"`
	PluginID          string         `json:"plugin_id"`
	PluginInstanceID  string         `json:"plugin_instance_id,omitempty"`
	SurfaceID         string         `json:"surface_id,omitempty"`
	SurfaceInstanceID string         `json:"surface_instance_id,omitempty"`
	RequestID         string         `json:"request_id,omitempty"`
	Actor             string         `json:"actor,omitempty"`
	OccurredAt        time.Time      `json:"occurred_at,omitempty"`
	Details           map[string]any `json:"details,omitempty"`
}

type DiagnosticEvent struct {
	EventID              string             `json:"event_id,omitempty"`
	Type                 string             `json:"type"`
	Severity             DiagnosticSeverity `json:"severity"`
	Message              string             `json:"message"`
	PluginID             string             `json:"plugin_id,omitempty"`
	PluginInstanceID     string             `json:"plugin_instance_id,omitempty"`
	SurfaceID            string             `json:"surface_id,omitempty"`
	SurfaceInstanceID    string             `json:"surface_instance_id,omitempty"`
	ActiveFingerprint    string             `json:"active_fingerprint,omitempty"`
	RequestID            string             `json:"request_id,omitempty"`
	CorrelationID        string             `json:"correlation_id,omitempty"`
	MutationOutcome      mutation.Outcome   `json:"mutation_outcome,omitempty"`
	OwnerSessionHash     string             `json:"-"`
	OwnerUserHash        string             `json:"-"`
	OwnerEnvHash         string             `json:"-"`
	SessionChannelIDHash string             `json:"-"`
	OccurredAt           time.Time          `json:"occurred_at,omitempty"`
	Details              DiagnosticDetails  `json:"details,omitempty"`
	Failure              Failure            `json:"-"`
}

type ListDiagnosticRequest struct {
	PluginID             string             `json:"plugin_id,omitempty"`
	PluginInstanceID     string             `json:"plugin_instance_id,omitempty"`
	SurfaceInstanceID    string             `json:"surface_instance_id,omitempty"`
	OwnerSessionHash     string             `json:"-"`
	OwnerUserHash        string             `json:"-"`
	OwnerEnvHash         string             `json:"-"`
	SessionChannelIDHash string             `json:"-"`
	Type                 string             `json:"type,omitempty"`
	Severity             DiagnosticSeverity `json:"severity,omitempty"`
	Limit                int                `json:"limit,omitempty"`
}

type MemoryStoreOptions struct {
	Now                 func() time.Time
	MaxAuditEvents      int
	MaxDiagnosticEvents int
}

type MemoryStore struct {
	mu                  sync.RWMutex
	now                 func() time.Time
	maxAuditEvents      int
	maxDiagnosticEvents int
	nextAuditSeq        uint64
	nextDiagnosticSeq   uint64
	auditEvents         fixedRing[AuditEvent]
	diagnosticEvents    fixedRing[DiagnosticEvent]
	securityJournal     *MemorySecurityAuditJournal
}

func NewMemoryStore(opts ...MemoryStoreOptions) *MemoryStore {
	options := MemoryStoreOptions{}
	if len(opts) > 0 {
		options = opts[0]
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	maxAuditEvents := options.MaxAuditEvents
	if maxAuditEvents <= 0 {
		maxAuditEvents = defaultMaxEvents
	}
	maxDiagnosticEvents := options.MaxDiagnosticEvents
	if maxDiagnosticEvents <= 0 {
		maxDiagnosticEvents = defaultMaxEvents
	}
	return &MemoryStore{
		now:                 now,
		maxAuditEvents:      maxAuditEvents,
		maxDiagnosticEvents: maxDiagnosticEvents,
		auditEvents:         newFixedRing[AuditEvent](maxAuditEvents),
		diagnosticEvents:    newFixedRing[DiagnosticEvent](maxDiagnosticEvents),
		securityJournal:     NewMemorySecurityAuditJournal(MemorySecurityAuditJournalOptions{Now: now, MaxEntries: maxAuditEvents}),
	}
}

func (s *MemoryStore) AppendPluginAudit(_ context.Context, event AuditEvent) error {
	if s == nil {
		return errors.New("observability store is nil")
	}
	event, err := normalizeAuditEvent(event, s.now)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if event.EventID != "" {
		for index := 0; index < s.auditEvents.count; index++ {
			stored := s.auditEvents.values[(s.auditEvents.start+index)%len(s.auditEvents.values)]
			if stored.EventID == event.EventID {
				return nil
			}
		}
	}
	s.nextAuditSeq++
	if event.EventID == "" {
		event.EventID = eventID("audit", s.nextAuditSeq)
	}
	s.auditEvents.Push(event)
	return nil
}

func (s *MemoryStore) AppendPluginDiagnostic(_ context.Context, event DiagnosticEvent) error {
	if s == nil {
		return errors.New("observability store is nil")
	}
	event, err := normalizeDiagnosticEvent(event, s.now)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextDiagnosticSeq++
	if strings.TrimSpace(event.EventID) == "" {
		event.EventID = eventID("diagnostic", s.nextDiagnosticSeq)
	}
	s.diagnosticEvents.Push(event)
	return nil
}

func (s *MemoryStore) ListPluginDiagnostics(_ context.Context, req ListDiagnosticRequest) ([]DiagnosticEvent, error) {
	if s == nil {
		return nil, errors.New("observability store is nil")
	}
	limit := normalizeLimit(req.Limit)
	pluginID := strings.TrimSpace(req.PluginID)
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	surfaceInstanceID := strings.TrimSpace(req.SurfaceInstanceID)
	ownerSessionHash, ownerUserHash, ownerEnvHash, sessionChannelIDHash, err := diagnosticOwnerScope(req)
	if err != nil {
		return nil, err
	}
	eventType := strings.TrimSpace(req.Type)
	severity, err := normalizeOptionalDiagnosticSeverity(req.Severity)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	diagnostics := s.diagnosticEvents.Snapshot()
	events := make([]DiagnosticEvent, 0, minInt(limit, len(diagnostics)))
	for _, event := range diagnostics {
		if pluginID != "" && event.PluginID != pluginID {
			continue
		}
		if pluginInstanceID != "" && event.PluginInstanceID != pluginInstanceID {
			continue
		}
		if surfaceInstanceID != "" && event.SurfaceInstanceID != surfaceInstanceID {
			continue
		}
		if event.OwnerSessionHash != ownerSessionHash {
			continue
		}
		if event.OwnerUserHash != ownerUserHash {
			continue
		}
		if event.OwnerEnvHash != ownerEnvHash {
			continue
		}
		if event.SessionChannelIDHash != sessionChannelIDHash {
			continue
		}
		if eventType != "" && event.Type != eventType {
			continue
		}
		if severity != "" && event.Severity != severity {
			continue
		}
		events = append(events, publicDiagnosticEvent(event))
	}
	sortDiagnosticEventsNewestFirst(events)
	if len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

func eventID(prefix string, seq uint64) string {
	return prefix + "_" + leftPadUint(seq, 12)
}

func leftPadUint(value uint64, width int) string {
	text := strconv.FormatUint(value, 10)
	for len(text) < width {
		text = "0" + text
	}
	return text
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return defaultListLimit
	}
	if limit > maxListLimit {
		return maxListLimit
	}
	return limit
}

func normalizeDiagnosticSeverity(severity DiagnosticSeverity) (DiagnosticSeverity, error) {
	normalized := DiagnosticSeverity(strings.TrimSpace(string(severity)))
	if normalized.Valid() {
		return normalized, nil
	}
	return "", ErrInvalidDiagnosticSeverity
}

func normalizeOptionalDiagnosticSeverity(severity DiagnosticSeverity) (DiagnosticSeverity, error) {
	if strings.TrimSpace(string(severity)) == "" {
		return "", nil
	}
	return normalizeDiagnosticSeverity(severity)
}

type fixedRing[T any] struct {
	values []T
	start  int
	count  int
}

func newFixedRing[T any](capacity int) fixedRing[T] {
	if capacity <= 0 {
		capacity = defaultMaxEvents
	}
	return fixedRing[T]{values: make([]T, capacity)}
}

func (r *fixedRing[T]) Push(value T) {
	if len(r.values) == 0 {
		return
	}
	if r.count < len(r.values) {
		r.values[(r.start+r.count)%len(r.values)] = value
		r.count++
		return
	}
	r.values[r.start] = value
	r.start = (r.start + 1) % len(r.values)
}

func (r fixedRing[T]) Snapshot() []T {
	result := make([]T, r.count)
	for index := 0; index < r.count; index++ {
		result[index] = r.values[(r.start+index)%len(r.values)]
	}
	return result
}

func (r fixedRing[T]) Len() int { return r.count }

func sortDiagnosticEventsNewestFirst(events []DiagnosticEvent) {
	sort.Slice(events, func(i, j int) bool {
		if events[i].OccurredAt.Equal(events[j].OccurredAt) {
			return events[i].EventID > events[j].EventID
		}
		return events[i].OccurredAt.After(events[j].OccurredAt)
	})
}

func cloneDiagnosticEvent(event DiagnosticEvent) DiagnosticEvent {
	return event
}

func publicDiagnosticEvent(event DiagnosticEvent) DiagnosticEvent {
	event = cloneDiagnosticEvent(event)
	event.Failure = Failure{}
	return event
}

func diagnosticOwnerScope(req ListDiagnosticRequest) (string, string, string, string, error) {
	ownerSessionHash := strings.TrimSpace(req.OwnerSessionHash)
	ownerUserHash := strings.TrimSpace(req.OwnerUserHash)
	ownerEnvHash := strings.TrimSpace(req.OwnerEnvHash)
	sessionChannelIDHash := strings.TrimSpace(req.SessionChannelIDHash)
	if ownerSessionHash == "" || ownerUserHash == "" || ownerEnvHash == "" || sessionChannelIDHash == "" {
		return "", "", "", "", ErrDiagnosticScopeRequired
	}
	return ownerSessionHash, ownerUserHash, ownerEnvHash, sessionChannelIDHash, nil
}

func normalizeAuditEvent(event AuditEvent, now func() time.Time) (AuditEvent, error) {
	event.EventID = strings.TrimSpace(event.EventID)
	event.Type = strings.TrimSpace(event.Type)
	event.PluginID = strings.TrimSpace(event.PluginID)
	event.PluginInstanceID = strings.TrimSpace(event.PluginInstanceID)
	event.SurfaceID = strings.TrimSpace(event.SurfaceID)
	event.SurfaceInstanceID = strings.TrimSpace(event.SurfaceInstanceID)
	event.RequestID = strings.TrimSpace(event.RequestID)
	event.Actor = strings.TrimSpace(event.Actor)
	if event.OccurredAt.IsZero() && now != nil {
		event.OccurredAt = now().UTC()
	} else {
		event.OccurredAt = event.OccurredAt.UTC()
	}
	cloned, err := cloneAuditDetails(event.Details)
	if err != nil {
		return AuditEvent{}, err
	}
	event.Details = cloned
	if err := ValidateAuditEvent(event); err != nil {
		return AuditEvent{}, err
	}
	return event, nil
}

func ValidateAuditEvent(event AuditEvent) error {
	if event.Type == "" || event.OccurredAt.IsZero() {
		return ErrInvalidEvent
	}
	for _, value := range []string{
		event.EventID, event.Type, event.PluginID, event.PluginInstanceID, event.SurfaceID,
		event.SurfaceInstanceID, event.RequestID, event.Actor,
	} {
		if value != "" && !validStableValue(value) {
			return ErrInvalidEvent
		}
	}
	if !validAuditDetails(event.Details) {
		return ErrInvalidAuditDetails
	}
	return nil
}

func validAuditDetails(details map[string]any) bool {
	for key, value := range details {
		switch key {
		case "audit_correlation_id", "effect", "execution", "intent_id",
			"invocation_id", "method", "operation_id", "plan_hash", "preflight_method", "route_kind",
			"runtime_generation_id", "runtime_instance_id", "source_plugin_instance_id", "status", "stream_id",
			"target_descriptor_sha256":
			text, ok := auditString(value)
			if !ok || !validStableValue(text) {
				return false
			}
		case "session_scope_state":
			text, ok := auditString(value)
			if !ok || !validSessionScopeState(text) {
				return false
			}
		case "capability_contract_artifact":
			text, ok := auditString(value)
			if !ok || !validPackageRelativePath(text) {
				return false
			}
		case "reason":
			text, ok := auditString(value)
			if !ok || !validAuditReason(text) {
				return false
			}
		case "mutation_outcome":
			text, ok := auditString(value)
			if !ok || !validMutationOutcome(mutation.Outcome(text)) {
				return false
			}
		case "channel_scoped", "delete_data", "runtime_revoked", "runtime_stopped",
			"session_scope_fenced", "session_scope_complete":
			if _, ok := value.(bool); !ok {
				return false
			}
		case "active_network_request_count", "asset_session_count", "asset_ticket_count",
			"closed_socket_count", "closed_storage_handle_count", "closed_stream_count", "confirmation_count",
			"confirmation_token_count", "execution_count", "expires_at_unix_ms", "gateway_token_count",
			"handle_grant_count", "management_revision", "network_stream_count", "operation_count",
			"policy_revision", "revoke_epoch", "revoked_surface_count", "runtime_execution_count",
			"socket_count", "storage_hostcall_count", "stream_count", "stream_ticket_count", "surface_count",
			"token_count":
			if !validAuditInteger(value) {
				return false
			}
		case "target_descriptor_hashes":
			switch values := value.(type) {
			case []string:
				for _, text := range values {
					if !validStableValue(text) {
						return false
					}
				}
			case []any:
				for _, item := range values {
					text, ok := item.(string)
					if !ok || !validStableValue(text) {
						return false
					}
				}
			default:
				return false
			}
		case "failure":
			if !validPersistedFailure(value) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validSessionScopeState(state string) bool {
	switch state {
	case "fenced", "draining", "incomplete", "complete":
		return true
	default:
		return false
	}
}

func auditString(value any) (string, bool) {
	if value == nil {
		return "", false
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() != reflect.String {
		return "", false
	}
	return reflected.String(), true
}

func validAuditReason(reason string) bool {
	switch reason {
	case "adapter_panic", "business_error", "confirmation_invalid", "confirmation_rejected",
		"confirmation_required", "execution_revoked", "lease_revoked", "pending_reconciled",
		"permission_denied", "policy_denied", "quota_exceeded", "remote_mismatch", "request_contract",
		"response_contract", "token_invalid", "trust_denied", "trust_unavailable", "unavailable":
		return true
	default:
		return false
	}
}

func validAuditInteger(value any) bool {
	switch number := value.(type) {
	case int:
		return number >= 0 && uint64(number) <= maxSafeInteger
	case int8:
		return number >= 0
	case int16:
		return number >= 0
	case int32:
		return number >= 0
	case int64:
		return number >= 0 && uint64(number) <= maxSafeInteger
	case uint:
		return uint64(number) <= maxSafeInteger
	case uint8:
		return true
	case uint16:
		return true
	case uint32:
		return true
	case uint64:
		return number <= maxSafeInteger
	case float32:
		value := float64(number)
		return value >= 0 && value <= float64(maxSafeInteger) && math.Trunc(value) == value
	case float64:
		return number >= 0 && number <= float64(maxSafeInteger) && math.Trunc(number) == number
	default:
		return false
	}
}

func validPersistedFailure(value any) bool {
	switch failure := value.(type) {
	case Failure:
		return failure.Valid()
	case *Failure:
		return failure != nil && failure.Valid()
	}
	fields, ok := value.(map[string]any)
	if !ok || len(fields) != 3 {
		return false
	}
	code, codeOK := fields["code"].(string)
	component, componentOK := fields["component"].(string)
	operation, operationOK := fields["operation"].(string)
	return codeOK && componentOK && operationOK && Failure{
		Code: FailureCode(code), Component: FailureComponent(component), Operation: FailureOperation(operation),
	}.Valid()
}

func normalizeDiagnosticEvent(event DiagnosticEvent, now func() time.Time) (DiagnosticEvent, error) {
	event.EventID = strings.TrimSpace(event.EventID)
	event.Type = strings.TrimSpace(event.Type)
	event.Message = strings.TrimSpace(event.Message)
	event.PluginID = strings.TrimSpace(event.PluginID)
	event.PluginInstanceID = strings.TrimSpace(event.PluginInstanceID)
	event.SurfaceID = strings.TrimSpace(event.SurfaceID)
	event.SurfaceInstanceID = strings.TrimSpace(event.SurfaceInstanceID)
	event.ActiveFingerprint = strings.TrimSpace(event.ActiveFingerprint)
	event.RequestID = strings.TrimSpace(event.RequestID)
	event.CorrelationID = strings.TrimSpace(event.CorrelationID)
	event.OwnerSessionHash = strings.TrimSpace(event.OwnerSessionHash)
	event.OwnerUserHash = strings.TrimSpace(event.OwnerUserHash)
	event.OwnerEnvHash = strings.TrimSpace(event.OwnerEnvHash)
	event.SessionChannelIDHash = strings.TrimSpace(event.SessionChannelIDHash)
	event.Failure.Operation = FailureOperation(strings.TrimSpace(string(event.Failure.Operation)))
	if event.OccurredAt.IsZero() && now != nil {
		event.OccurredAt = now()
	}
	if err := ValidateDiagnosticEvent(event); err != nil {
		return DiagnosticEvent{}, err
	}
	return event, nil
}

func ValidateDiagnosticEvent(event DiagnosticEvent) error {
	if event.Type == "" {
		return ErrInvalidEvent
	}
	severity, err := normalizeDiagnosticSeverity(event.Severity)
	if err != nil || severity != event.Severity {
		return ErrInvalidDiagnosticSeverity
	}
	if !validDiagnosticPresentation(event.Type, event.Severity, event.Message) {
		return ErrInvalidDiagnosticMessage
	}
	for _, value := range []string{
		event.EventID, event.PluginID, event.PluginInstanceID, event.SurfaceID, event.SurfaceInstanceID,
		event.ActiveFingerprint, event.RequestID, event.CorrelationID, event.OwnerSessionHash, event.OwnerUserHash,
		event.OwnerEnvHash, event.SessionChannelIDHash,
	} {
		if value != "" && !validStableValue(value) {
			return ErrInvalidEvent
		}
	}
	if event.OccurredAt.IsZero() {
		return ErrInvalidEvent
	}
	if event.MutationOutcome != "" && event.MutationOutcome != mutation.OutcomeCommitted &&
		event.MutationOutcome != mutation.OutcomeNotCommitted && event.MutationOutcome != mutation.OutcomeUnknown {
		return ErrInvalidEvent
	}
	if !event.Details.Valid() {
		return ErrInvalidDiagnosticDetails
	}
	if !event.Failure.Empty() && !event.Failure.Valid() {
		return ErrInvalidDiagnosticFailure
	}
	return nil
}

func validDiagnosticPresentation(eventType string, severity DiagnosticSeverity, message string) bool {
	switch eventType {
	case "plugin.csp.violation":
		return severity == DiagnosticSeverityInfo && message == "plugin content security policy violation"
	case "plugin.execution.retention_pruned":
		return severity == DiagnosticSeverityInfo && message == "terminal operation and stream retention was pruned"
	case "plugin.execution.retention_prune_failed":
		return severity == DiagnosticSeverityWarning && message == "terminal execution retention pruning failed"
	case "plugin.execution.failed":
		return severity == DiagnosticSeverityWarning && message == "execution failed"
	case "plugin.execution.duration_terminal_failed":
		return severity == DiagnosticSeverityWarning && message == "duration quota terminal state could not be persisted"
	case "plugin.install_stage.commit_failed":
		return severity == DiagnosticSeverityWarning && message == "plugin install stage commit failed"
	case "plugin.method.rejected":
		return severity == DiagnosticSeverityWarning && message == "plugin method was rejected"
	case "plugin.runtime.stop_failed":
		return severity == DiagnosticSeverityWarning && message == "plugin runtime stop failed"
	case "plugin.runtime.warning":
		return severity == DiagnosticSeverityWarning && message == "runtime warning"
	case "plugin.runtime_capabilities.revoke_failed":
		return severity == DiagnosticSeverityWarning && message == "plugin runtime capability revocation failed"
	case "plugin.runtime_state.refresh_failed":
		return severity == DiagnosticSeverityWarning && message == "plugin runtime state refresh failed"
	case "plugin.secret.adapter_failed":
		return severity == DiagnosticSeverityWarning && message == "secret adapter operation failed"
	case "plugin.security_audit.export_failed":
		return severity == DiagnosticSeverityWarning && message == "security audit export failed"
	case "plugin.security_event.persistence_failed":
		return severity == DiagnosticSeverityWarning && message == "security event persistence failed"
	case "plugin.http.operation_failed":
		return severity == DiagnosticSeverityWarning && message == "plugin HTTP operation failed"
	case "plugin.surface.renderer_error":
		return severity == DiagnosticSeverityWarning && message == "plugin surface renderer failed"
	case "plugin.runtime.process.started":
		return severity == DiagnosticSeverityInfo && message == "runtime process started"
	case "plugin.runtime.process.cleanup_timeout":
		return severity == DiagnosticSeverityWarning && message == "runtime process did not exit after failed handshake"
	case "plugin.runtime.ipc.handshake":
		return severity == DiagnosticSeverityInfo && message == "runtime IPC handshake completed"
	case "plugin.runtime.lease.signature_rejected":
		return severity == DiagnosticSeverityWarning && message == "runtime execution lease signature was rejected"
	case "plugin.runtime.lease.replayed":
		return severity == DiagnosticSeverityWarning && message == "runtime execution lease was already consumed"
	case "plugin.runtime.process.stopped":
		return severity == DiagnosticSeverityInfo && message == "runtime process stopped"
	case "plugin.runtime.process.exited":
		return severity == DiagnosticSeverityInfo && message == "runtime process exited" ||
			severity == DiagnosticSeverityWarning && message == "runtime process exited with error"
	case "plugin.runtime.process.stdout":
		return severity == DiagnosticSeverityInfo && message == "runtime process wrote to stdout"
	case "plugin.runtime.process.stderr":
		return severity == DiagnosticSeverityWarning && message == "runtime process wrote to stderr"
	case "plugin.runtime.process.stdout.error", "plugin.runtime.process.stderr.error":
		return severity == DiagnosticSeverityWarning && message == "runtime process output could not be read"
	case "plugin.runtime.hostcall.failed":
		return severity == DiagnosticSeverityWarning && message == "runtime hostcall failed"
	case "plugin.runtime.ipc.invalidated":
		return severity == DiagnosticSeverityWarning && message == "runtime IPC channel was invalidated"
	default:
		return false
	}
}

func validStableValue(value string) bool {
	return value == strings.TrimSpace(value) && stableValuePattern.MatchString(value)
}

func validPackageRelativePath(value string) bool {
	if value == "" || len(value) > 512 || strings.ContainsAny(value, `\\?#`) || strings.HasPrefix(value, "/") {
		return false
	}
	cleaned := path.Clean(value)
	return cleaned == value && cleaned != "." && cleaned != ".." && !strings.HasPrefix(cleaned, "../")
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
