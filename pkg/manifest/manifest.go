package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/version"
)

type Manifest struct {
	SchemaVersion      string              `json:"schema_version"`
	Publisher          Publisher           `json:"publisher"`
	Plugin             Plugin              `json:"plugin"`
	Surfaces           []SurfaceSpec       `json:"surfaces,omitempty"`
	CapabilityBindings []CapabilityBinding `json:"capability_bindings,omitempty"`
	Methods            []MethodSpec        `json:"methods,omitempty"`
	Workers            []WorkerSpec        `json:"workers,omitempty"`
	Storage            *StorageSpec        `json:"storage,omitempty"`
	NetworkAccess      *NetworkAccessSpec  `json:"network_access,omitempty"`
	Settings           *SettingsSpec       `json:"settings,omitempty"`
	Intents            []IntentSpec        `json:"intents,omitempty"`
}

type Publisher struct {
	PublisherID string `json:"publisher_id"`
	DisplayName string `json:"display_name,omitempty"`
}

type Plugin struct {
	PluginID          string `json:"plugin_id"`
	DisplayName       string `json:"display_name"`
	Version           string `json:"version"`
	APIVersion        string `json:"api_version"`
	MinRuntimeVersion string `json:"min_runtime_version"`
	UIProtocolVersion string `json:"ui_protocol_version"`
}

func (m Manifest) PluginID() string {
	return m.Plugin.PluginID
}

func (m Manifest) Version() string {
	return m.Plugin.Version
}

func (m Manifest) APIVersion() string {
	return m.Plugin.APIVersion
}

type CapabilityBinding struct {
	BindingID string                 `json:"binding_id"`
	Contract  capabilitycontract.Pin `json:"contract"`
}

type MethodEffect string

const (
	MethodEffectRead    MethodEffect = "read"
	MethodEffectWrite   MethodEffect = "write"
	MethodEffectExecute MethodEffect = "execute"
	MethodEffectDelete  MethodEffect = "delete"
	MethodEffectAdmin   MethodEffect = "admin"
)

type MethodExecutionMode string

const (
	MethodExecutionSync         MethodExecutionMode = "sync"
	MethodExecutionOperation    MethodExecutionMode = "operation"
	MethodExecutionSubscription MethodExecutionMode = "subscription"
)

type MethodRouteKind string

const (
	MethodRouteCapability MethodRouteKind = "capability"
	MethodRouteWorker     MethodRouteKind = "worker"
	MethodRouteCoreAction MethodRouteKind = "core_action"
)

type MethodRouteSpec struct {
	Kind         MethodRouteKind `json:"kind"`
	BindingID    string          `json:"binding_id,omitempty"`
	TargetMethod string          `json:"target_method,omitempty"`
	WorkerID     string          `json:"worker_id,omitempty"`
	ActionID     string          `json:"action_id,omitempty"`
}

type MethodSpec struct {
	Method         string                  `json:"method"`
	Effect         MethodEffect            `json:"effect,omitempty"`
	Execution      MethodExecutionMode     `json:"execution,omitempty"`
	Dangerous      bool                    `json:"dangerous,omitempty"`
	PreflightOnly  bool                    `json:"preflight_only,omitempty"`
	Confirmation   *ConfirmationSpec       `json:"confirmation,omitempty"`
	CancelPolicy   *CancelPolicySpec       `json:"cancel_policy,omitempty"`
	RequestSchema  map[string]any          `json:"request_schema,omitempty"`
	ResponseSchema map[string]any          `json:"response_schema,omitempty"`
	Route          MethodRouteSpec         `json:"route"`
	BrokerAccess   *MethodBrokerAccessSpec `json:"broker_access,omitempty"`
}

type MethodBrokerAccessSpec struct {
	Storage []StorageBrokerAccessSpec `json:"storage,omitempty"`
	Network []NetworkBrokerAccessSpec `json:"network,omitempty"`
}

type StorageBrokerAccessSpec struct {
	StoreID    string   `json:"store_id"`
	Operations []string `json:"operations"`
}

type NetworkBrokerAccessSpec struct {
	ConnectorID string   `json:"connector_id"`
	Transport   string   `json:"transport"`
	Scope       string   `json:"scope,omitempty"`
	Operations  []string `json:"operations"`
	HTTPMethods []string `json:"http_methods,omitempty"`
}

type ConfirmationMode string

const (
	ConfirmationNone      ConfirmationMode = "none"
	ConfirmationRequired  ConfirmationMode = "required"
	ConfirmationRiskBased ConfirmationMode = "risk_based"
)

type ConfirmationSpec struct {
	Mode              ConfirmationMode `json:"mode"`
	PreflightMethod   *string          `json:"preflight_method,omitempty"`
	RequestHashFields []string         `json:"request_hash_fields,omitempty"`
	PlanHashRequired  bool             `json:"plan_hash_required,omitempty"`
}

type CancelPolicySpec struct {
	Cancelable        bool   `json:"cancelable"`
	DisableBehavior   string `json:"disable_behavior,omitempty"`
	UninstallBehavior string `json:"uninstall_behavior,omitempty"`
	AckTimeoutMS      int    `json:"ack_timeout_ms,omitempty"`
}

const (
	CancelDisableBehaviorCancel = "cancel"
	CancelDisableBehaviorOrphan = "orphan"
	CancelDisableBehaviorWait   = "wait"

	CancelUninstallBehaviorCancelThenBlockDelete = "cancel_then_block_delete"
	CancelUninstallBehaviorForceCleanupAllowed   = "force_cleanup_allowed"
)

type SurfaceKind string

const (
	SurfaceView       SurfaceKind = "view"
	SurfaceCommand    SurfaceKind = "command"
	SurfaceBackground SurfaceKind = "background"
)

type SurfaceIntent string

const (
	SurfaceIntentPrimary   SurfaceIntent = "primary"
	SurfaceIntentSecondary SurfaceIntent = "secondary"
	SurfaceIntentUtility   SurfaceIntent = "utility"
)

type SurfaceSpec struct {
	SurfaceID   string          `json:"surface_id"`
	Kind        SurfaceKind     `json:"kind"`
	Intent      SurfaceIntent   `json:"intent,omitempty"`
	Label       string          `json:"label"`
	Entry       string          `json:"entry"`
	Icon        string          `json:"icon,omitempty"`
	DefaultSize *WidgetSizeSpec `json:"default_size,omitempty"`
}

type WidgetSizeSpec struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

type WorkerMode string

const (
	WorkerModeJob             WorkerMode = "job"
	MaxWorkerMemoryLimitBytes int64      = 256 << 20
	MaxStorageStores                     = 16
	MaxStoreQuotaBytes        int64      = 1 << 30
	MaxStoreQuotaFiles        int64      = 100_000
	DefaultStoreQuotaFiles    int64      = 10_000
)

type WorkerSpec struct {
	WorkerID         string     `json:"worker_id"`
	Artifact         string     `json:"artifact"`
	ABI              string     `json:"abi"`
	Mode             WorkerMode `json:"mode"`
	Scope            string     `json:"scope"`
	MemoryLimitBytes int64      `json:"memory_limit_bytes"`
	IdleTimeoutMS    int        `json:"idle_timeout_ms,omitempty"`
}

type StorageSpec struct {
	Stores []StoreSpec `json:"stores,omitempty"`
}

type StoreSpec struct {
	StoreID       string `json:"store_id"`
	Kind          string `json:"kind"`
	Scope         string `json:"scope"`
	QuotaBytes    int64  `json:"quota_bytes"`
	QuotaFiles    *int64 `json:"quota_files,omitempty"`
	SchemaVersion int    `json:"schema_version"`
}

type NetworkAccessSpec struct {
	Connectors []NetworkConnectorSpec `json:"connectors,omitempty"`
}

type NetworkConnectorSpec struct {
	ConnectorID  string         `json:"connector_id"`
	Transport    string         `json:"transport"`
	Scope        string         `json:"scope"`
	Destinations []string       `json:"destinations"`
	Auth         map[string]any `json:"auth,omitempty"`
	TLS          map[string]any `json:"tls,omitempty"`
}

type SettingsSpec struct {
	SchemaVersion int                `json:"schema_version"`
	Fields        []SettingFieldSpec `json:"fields,omitempty"`
}

type SettingFieldSpec struct {
	Key        string         `json:"key"`
	Type       string         `json:"type"`
	Label      string         `json:"label"`
	Scope      string         `json:"scope"`
	Default    any            `json:"default,omitempty"`
	SecretRef  string         `json:"secret_ref,omitempty"`
	Options    []string       `json:"options,omitempty"`
	Validation map[string]any `json:"validation,omitempty"`
}

type IntentSpec struct {
	IntentID      string         `json:"intent_id"`
	Method        string         `json:"method"`
	PayloadSchema map[string]any `json:"payload_schema,omitempty"`
}

type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return e.Field + ": " + e.Message
}

func Decode(r io.Reader) (Manifest, error) {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()

	var m Manifest
	if err := decoder.Decode(&m); err != nil {
		return Manifest{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return Manifest{}, err
		}
		return Manifest{}, errors.New("manifest contains trailing JSON values")
	}
	return m, Validate(m)
}

func Validate(m Manifest) error {
	if m.SchemaVersion != "redevplugin.manifest.v5" {
		return ValidationError{Field: "schema_version", Message: "must be redevplugin.manifest.v5"}
	}
	if strings.TrimSpace(m.Publisher.PublisherID) == "" {
		return ValidationError{Field: "publisher.publisher_id", Message: "is required"}
	}
	if strings.TrimSpace(m.Plugin.PluginID) == "" {
		return ValidationError{Field: "plugin.plugin_id", Message: "is required"}
	}
	if strings.TrimSpace(m.Plugin.DisplayName) == "" {
		return ValidationError{Field: "plugin.display_name", Message: "is required"}
	}
	if _, err := version.ParseSemVer(m.Plugin.Version); err != nil {
		return ValidationError{Field: "plugin.version", Message: "must be a strict semantic version"}
	}
	if m.Plugin.APIVersion != "plugin-v1" {
		return ValidationError{Field: "plugin.api_version", Message: "must be plugin-v1"}
	}
	if m.Plugin.UIProtocolVersion != version.PluginUIProtocolVersion {
		return ValidationError{Field: "plugin.ui_protocol_version", Message: "must be " + version.PluginUIProtocolVersion}
	}
	if _, err := version.ParseSemVer(m.Plugin.MinRuntimeVersion); err != nil {
		return ValidationError{Field: "plugin.min_runtime_version", Message: "must be a strict semantic version"}
	}
	if m.Surfaces == nil {
		return ValidationError{Field: "surfaces", Message: "is required"}
	}

	bindings := map[string]struct{}{}
	for i, binding := range m.CapabilityBindings {
		if binding.BindingID == "" {
			return ValidationError{Field: fmt.Sprintf("capability_bindings[%d].binding_id", i), Message: "is required"}
		}
		if _, ok := bindings[binding.BindingID]; ok {
			return ValidationError{Field: fmt.Sprintf("capability_bindings[%d].binding_id", i), Message: "must be unique"}
		}
		bindings[binding.BindingID] = struct{}{}
		if err := capabilitycontract.ValidatePin(binding.Contract); err != nil {
			return ValidationError{Field: fmt.Sprintf("capability_bindings[%d].contract", i), Message: err.Error()}
		}
	}

	workers := map[string]struct{}{}
	for i, worker := range m.Workers {
		if strings.TrimSpace(worker.WorkerID) == "" {
			return ValidationError{Field: fmt.Sprintf("workers[%d].worker_id", i), Message: "is required"}
		}
		if _, ok := workers[worker.WorkerID]; ok {
			return ValidationError{Field: fmt.Sprintf("workers[%d].worker_id", i), Message: "must be unique"}
		}
		workers[worker.WorkerID] = struct{}{}
		if strings.TrimSpace(worker.Artifact) == "" {
			return ValidationError{Field: fmt.Sprintf("workers[%d].artifact", i), Message: "is required"}
		}
		if worker.ABI != "redevplugin-wasm-worker-v2" {
			return ValidationError{Field: fmt.Sprintf("workers[%d].abi", i), Message: "must be redevplugin-wasm-worker-v2"}
		}
		if worker.Mode != WorkerModeJob {
			return ValidationError{Field: fmt.Sprintf("workers[%d].mode", i), Message: "must be job"}
		}
		if worker.Scope != "user" && worker.Scope != "environment" {
			return ValidationError{Field: fmt.Sprintf("workers[%d].scope", i), Message: "must be user or environment"}
		}
		if worker.MemoryLimitBytes <= 0 {
			return ValidationError{Field: fmt.Sprintf("workers[%d].memory_limit_bytes", i), Message: "must be positive"}
		}
		if worker.MemoryLimitBytes > MaxWorkerMemoryLimitBytes {
			return ValidationError{Field: fmt.Sprintf("workers[%d].memory_limit_bytes", i), Message: fmt.Sprintf("must not exceed %d", MaxWorkerMemoryLimitBytes)}
		}
		if worker.IdleTimeoutMS < 0 {
			return ValidationError{Field: fmt.Sprintf("workers[%d].idle_timeout_ms", i), Message: "must not be negative"}
		}
	}

	methods := map[string]MethodSpec{}
	for i, method := range m.Methods {
		if method.Method == "" {
			return ValidationError{Field: fmt.Sprintf("methods[%d].method", i), Message: "is required"}
		}
		if _, ok := methods[method.Method]; ok {
			return ValidationError{Field: fmt.Sprintf("methods[%d].method", i), Message: "must be unique"}
		}
		if err := validateMethodRoute(fmt.Sprintf("methods[%d].route", i), method.Route, bindings, workers); err != nil {
			return err
		}
		if method.Route.Kind == MethodRouteCapability {
			if method.Method != method.Route.TargetMethod {
				return ValidationError{Field: fmt.Sprintf("methods[%d].method", i), Message: "must match route.target_method for capability routes"}
			}
			if capabilityMethodDeclaresUnsignedPolicy(method) {
				return ValidationError{Field: fmt.Sprintf("methods[%d]", i), Message: "capability routes must derive policy and schemas from the signed capability contract"}
			}
			methods[method.Method] = method
			continue
		}
		if !validEffect(method.Effect) {
			return ValidationError{Field: fmt.Sprintf("methods[%d].effect", i), Message: "is invalid"}
		}
		if !validExecutionMode(method.Execution) {
			return ValidationError{Field: fmt.Sprintf("methods[%d].execution", i), Message: "is invalid"}
		}
		if err := validateMethodConfirmation(fmt.Sprintf("methods[%d]", i), method); err != nil {
			return err
		}
		if err := validateMethodCancelPolicy(fmt.Sprintf("methods[%d]", i), method); err != nil {
			return err
		}
		if _, err := CompileMethodSchemas(method); err != nil {
			var schemaErr methodSchemaError
			if errors.As(err, &schemaErr) {
				return ValidationError{Field: fmt.Sprintf("methods[%d].%s", i, schemaErr.path), Message: schemaErr.message}
			}
			return ValidationError{Field: fmt.Sprintf("methods[%d]", i), Message: err.Error()}
		}
		methods[method.Method] = method
	}
	for i, method := range m.Methods {
		if method.Route.Kind == MethodRouteCapability {
			continue
		}
		if method.Confirmation == nil || method.Confirmation.PreflightMethod == nil {
			continue
		}
		preflightMethodName := strings.TrimSpace(*method.Confirmation.PreflightMethod)
		preflight, ok := methods[preflightMethodName]
		if !ok {
			return ValidationError{Field: fmt.Sprintf("methods[%d].confirmation.preflight_method", i), Message: "must reference a declared method"}
		}
		if preflight.Method == method.Method {
			return ValidationError{Field: fmt.Sprintf("methods[%d].confirmation.preflight_method", i), Message: "must not reference the same method"}
		}
		if !preflight.PreflightOnly {
			return ValidationError{Field: fmt.Sprintf("methods[%d].confirmation.preflight_method", i), Message: "must reference a preflight_only method"}
		}
		if preflight.Effect != MethodEffectRead {
			return ValidationError{Field: fmt.Sprintf("methods[%d].confirmation.preflight_method", i), Message: "must reference a read-only method"}
		}
		if preflight.Execution != MethodExecutionSync {
			return ValidationError{Field: fmt.Sprintf("methods[%d].confirmation.preflight_method", i), Message: "must reference a sync method"}
		}
	}

	surfaces := map[string]struct{}{}
	for i, surface := range m.Surfaces {
		if strings.TrimSpace(surface.SurfaceID) == "" {
			return ValidationError{Field: fmt.Sprintf("surfaces[%d].surface_id", i), Message: "is required"}
		}
		if _, ok := surfaces[surface.SurfaceID]; ok {
			return ValidationError{Field: fmt.Sprintf("surfaces[%d].surface_id", i), Message: "must be globally unique"}
		}
		surfaces[surface.SurfaceID] = struct{}{}
		if !validSurfaceKind(surface.Kind) {
			return ValidationError{Field: fmt.Sprintf("surfaces[%d].kind", i), Message: "must be view, command, or background"}
		}
		if surface.Intent != "" && !validSurfaceIntent(surface.Intent) {
			return ValidationError{Field: fmt.Sprintf("surfaces[%d].intent", i), Message: "must be primary, secondary, or utility"}
		}
		if strings.TrimSpace(surface.Label) == "" {
			return ValidationError{Field: fmt.Sprintf("surfaces[%d].label", i), Message: "is required"}
		}
		if strings.TrimSpace(surface.Entry) == "" {
			return ValidationError{Field: fmt.Sprintf("surfaces[%d].entry", i), Message: "is required"}
		}
		if err := validateSurfaceIcon(surface.Icon); err != nil {
			return ValidationError{Field: fmt.Sprintf("surfaces[%d].icon", i), Message: err.Error()}
		}
		if surface.DefaultSize != nil && surface.DefaultSize.Width <= 0 {
			return ValidationError{Field: fmt.Sprintf("surfaces[%d].default_size.width", i), Message: "must be positive"}
		}
		if surface.DefaultSize != nil && surface.DefaultSize.Height <= 0 {
			return ValidationError{Field: fmt.Sprintf("surfaces[%d].default_size.height", i), Message: "must be positive"}
		}
	}

	for i, intent := range m.Intents {
		if strings.TrimSpace(intent.IntentID) == "" {
			return ValidationError{Field: fmt.Sprintf("intents[%d].intent_id", i), Message: "is required"}
		}
		if _, ok := methods[intent.Method]; !ok {
			return ValidationError{Field: fmt.Sprintf("intents[%d].method", i), Message: "must reference a declared method"}
		}
	}

	if m.Settings != nil {
		if m.Settings.SchemaVersion <= 0 {
			return ValidationError{Field: "settings.schema_version", Message: "must be positive"}
		}
		settingsFields := map[string]struct{}{}
		for i, field := range m.Settings.Fields {
			if strings.TrimSpace(field.Key) == "" {
				return ValidationError{Field: fmt.Sprintf("settings.fields[%d].key", i), Message: "is required"}
			}
			if _, ok := settingsFields[field.Key]; ok {
				return ValidationError{Field: fmt.Sprintf("settings.fields[%d].key", i), Message: "must be unique"}
			}
			settingsFields[field.Key] = struct{}{}
			if field.Scope != "user" && field.Scope != "environment" {
				return ValidationError{Field: fmt.Sprintf("settings.fields[%d].scope", i), Message: "must be user or environment"}
			}
			if !validSettingType(field.Type) {
				return ValidationError{Field: fmt.Sprintf("settings.fields[%d].type", i), Message: "must be string, boolean, number, integer, enum, select, or secret"}
			}
			if strings.TrimSpace(field.Label) == "" {
				return ValidationError{Field: fmt.Sprintf("settings.fields[%d].label", i), Message: "is required"}
			}
			if (field.Type == "enum" || field.Type == "select") && len(field.Options) == 0 {
				return ValidationError{Field: fmt.Sprintf("settings.fields[%d].options", i), Message: "is required for option settings"}
			}
			if field.Type == "secret" && strings.TrimSpace(field.SecretRef) == "" {
				return ValidationError{Field: fmt.Sprintf("settings.fields[%d].secret_ref", i), Message: "is required for secret settings"}
			}
			if field.Type != "secret" && strings.TrimSpace(field.SecretRef) != "" {
				return ValidationError{Field: fmt.Sprintf("settings.fields[%d].secret_ref", i), Message: "is only allowed for secret settings"}
			}
		}
	}
	if m.Storage != nil {
		if len(m.Storage.Stores) > MaxStorageStores {
			return ValidationError{Field: "storage.stores", Message: fmt.Sprintf("must contain at most %d stores", MaxStorageStores)}
		}
		stores := map[string]string{}
		for i, store := range m.Storage.Stores {
			field := fmt.Sprintf("storage.stores[%d]", i)
			if strings.TrimSpace(store.StoreID) == "" {
				return ValidationError{Field: field + ".store_id", Message: "is required"}
			}
			if _, ok := stores[store.StoreID]; ok {
				return ValidationError{Field: field + ".store_id", Message: "must be unique"}
			}
			if !validStoreKind(store.Kind) {
				return ValidationError{Field: field + ".kind", Message: "must be files, kv, or sqlite"}
			}
			stores[store.StoreID] = store.Kind
			if store.Scope != "user" && store.Scope != "environment" {
				return ValidationError{Field: field + ".scope", Message: "must be user or environment"}
			}
			if store.QuotaBytes <= 0 {
				return ValidationError{Field: field + ".quota_bytes", Message: "must be positive"}
			}
			if store.QuotaBytes > MaxStoreQuotaBytes {
				return ValidationError{Field: field + ".quota_bytes", Message: fmt.Sprintf("must not exceed %d", MaxStoreQuotaBytes)}
			}
			if store.QuotaFiles != nil && *store.QuotaFiles <= 0 {
				return ValidationError{Field: field + ".quota_files", Message: "must be positive"}
			}
			if store.QuotaFiles != nil && *store.QuotaFiles > MaxStoreQuotaFiles {
				return ValidationError{Field: field + ".quota_files", Message: fmt.Sprintf("must not exceed %d", MaxStoreQuotaFiles)}
			}
			if store.SchemaVersion <= 0 {
				return ValidationError{Field: field + ".schema_version", Message: "must be positive"}
			}
		}
	}
	if m.NetworkAccess != nil {
		connectors := map[string]struct{}{}
		for i, connector := range m.NetworkAccess.Connectors {
			if strings.TrimSpace(connector.ConnectorID) == "" {
				return ValidationError{Field: fmt.Sprintf("network_access.connectors[%d].connector_id", i), Message: "is required"}
			}
			if _, ok := connectors[connector.ConnectorID]; ok {
				return ValidationError{Field: fmt.Sprintf("network_access.connectors[%d].connector_id", i), Message: "must be unique"}
			}
			connectors[connector.ConnectorID] = struct{}{}
			if !validNetworkTransport(connector.Transport) {
				return ValidationError{Field: fmt.Sprintf("network_access.connectors[%d].transport", i), Message: "must be http, websocket, tcp, or udp"}
			}
			if connector.Scope != "user" && connector.Scope != "environment" {
				return ValidationError{Field: fmt.Sprintf("network_access.connectors[%d].scope", i), Message: "must be user or environment"}
			}
			if len(connector.Destinations) == 0 {
				return ValidationError{Field: fmt.Sprintf("network_access.connectors[%d].destinations", i), Message: "must not be empty"}
			}
			for destinationIndex, destination := range connector.Destinations {
				if strings.TrimSpace(destination) == "" {
					return ValidationError{Field: fmt.Sprintf("network_access.connectors[%d].destinations[%d]", i, destinationIndex), Message: "must not be empty"}
				}
			}
		}
	}
	if err := validateSecretRefScopes(m); err != nil {
		return err
	}

	storeKinds := map[string]string{}
	if m.Storage != nil {
		for _, store := range m.Storage.Stores {
			storeKinds[store.StoreID] = store.Kind
		}
	}
	connectorTransports := map[string]string{}
	if m.NetworkAccess != nil {
		for _, connector := range m.NetworkAccess.Connectors {
			connectorTransports[connector.ConnectorID] = connector.Transport
		}
	}
	for i, method := range m.Methods {
		if err := validateMethodBrokerAccess(fmt.Sprintf("methods[%d].broker_access", i), method, storeKinds, connectorTransports); err != nil {
			return err
		}
	}

	return nil
}

type secretRefScopeDeclaration struct {
	scope string
	field string
}

func validateSecretRefScopes(m Manifest) error {
	declared := map[string]secretRefScopeDeclaration{}
	register := func(secretRef, scope, field string) error {
		secretRef = strings.TrimSpace(secretRef)
		if secretRef == "" {
			return nil
		}
		if existing, ok := declared[secretRef]; ok && existing.scope != scope {
			return ValidationError{
				Field:   field,
				Message: fmt.Sprintf("secret_ref %q is already declared with %s scope at %s", secretRef, existing.scope, existing.field),
			}
		}
		declared[secretRef] = secretRefScopeDeclaration{scope: scope, field: field}
		return nil
	}
	if m.Settings != nil {
		for index, field := range m.Settings.Fields {
			if field.Type != "secret" {
				continue
			}
			if err := register(field.SecretRef, field.Scope, fmt.Sprintf("settings.fields[%d].secret_ref", index)); err != nil {
				return err
			}
		}
	}
	if m.NetworkAccess != nil {
		for index, connector := range m.NetworkAccess.Connectors {
			for _, declaration := range []struct {
				field  string
				values map[string]any
			}{
				{field: fmt.Sprintf("network_access.connectors[%d].auth", index), values: connector.Auth},
				{field: fmt.Sprintf("network_access.connectors[%d].tls", index), values: connector.TLS},
			} {
				for _, secretRef := range declaredSecretRefs(declaration.values) {
					if err := register(secretRef, connector.Scope, declaration.field); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func declaredSecretRefs(values map[string]any) []string {
	refs := make([]string, 0, 1)
	var visit func(any)
	visit = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, nested := range typed {
				if strings.EqualFold(key, "secret_ref") {
					if secretRef, ok := nested.(string); ok && strings.TrimSpace(secretRef) != "" {
						refs = append(refs, strings.TrimSpace(secretRef))
					}
				}
				visit(nested)
			}
		case []any:
			for _, nested := range typed {
				visit(nested)
			}
		}
	}
	visit(values)
	sort.Strings(refs)
	return refs
}

func capabilityMethodDeclaresUnsignedPolicy(method MethodSpec) bool {
	return method.Effect != "" || method.Execution != "" || method.Dangerous || method.PreflightOnly ||
		method.Confirmation != nil || method.CancelPolicy != nil || method.RequestSchema != nil || method.ResponseSchema != nil || method.BrokerAccess != nil
}

func validateMethodBrokerAccess(field string, method MethodSpec, stores map[string]string, connectors map[string]string) error {
	access := method.BrokerAccess
	if access == nil {
		return nil
	}
	if method.Route.Kind != MethodRouteWorker {
		return ValidationError{Field: field, Message: "is only allowed for worker routes"}
	}
	seenStores := map[string]struct{}{}
	for i, item := range access.Storage {
		itemField := fmt.Sprintf("%s.storage[%d]", field, i)
		kind, ok := stores[item.StoreID]
		if !ok || strings.TrimSpace(item.StoreID) == "" {
			return ValidationError{Field: itemField + ".store_id", Message: "must reference a declared store"}
		}
		if _, duplicate := seenStores[item.StoreID]; duplicate {
			return ValidationError{Field: itemField + ".store_id", Message: "must be unique"}
		}
		seenStores[item.StoreID] = struct{}{}
		if len(item.Operations) == 0 {
			return ValidationError{Field: itemField + ".operations", Message: "must not be empty"}
		}
		seenOperations := map[string]struct{}{}
		for operationIndex, operation := range item.Operations {
			operationField := fmt.Sprintf("%s.operations[%d]", itemField, operationIndex)
			if !validStorageOperation(kind, operation) {
				return ValidationError{Field: operationField, Message: "is not valid for the declared store kind"}
			}
			if method.Effect == MethodEffectRead && !readOnlyStorageOperation(operation) {
				return ValidationError{Field: operationField, Message: "must be read-only for a read effect method"}
			}
			if _, duplicate := seenOperations[operation]; duplicate {
				return ValidationError{Field: operationField, Message: "must be unique"}
			}
			seenOperations[operation] = struct{}{}
		}
	}
	seenConnectors := map[string]struct{}{}
	for i, item := range access.Network {
		itemField := fmt.Sprintf("%s.network[%d]", field, i)
		if strings.TrimSpace(item.Scope) != "" {
			return ValidationError{Field: itemField + ".scope", Message: "is host-derived and must not be declared"}
		}
		transport, ok := connectors[item.ConnectorID]
		if !ok || strings.TrimSpace(item.ConnectorID) == "" {
			return ValidationError{Field: itemField + ".connector_id", Message: "must reference a declared connector"}
		}
		if _, duplicate := seenConnectors[item.ConnectorID]; duplicate {
			return ValidationError{Field: itemField + ".connector_id", Message: "must be unique"}
		}
		seenConnectors[item.ConnectorID] = struct{}{}
		if item.Transport != transport {
			return ValidationError{Field: itemField + ".transport", Message: "must match the declared connector transport"}
		}
		if len(item.Operations) == 0 {
			return ValidationError{Field: itemField + ".operations", Message: "must not be empty"}
		}
		seenOperations := map[string]struct{}{}
		for operationIndex, operation := range item.Operations {
			operationField := fmt.Sprintf("%s.operations[%d]", itemField, operationIndex)
			if !validNetworkOperation(item.Transport, operation) {
				return ValidationError{Field: operationField, Message: "is not valid for the declared transport"}
			}
			if method.Effect == MethodEffectRead && item.Transport != "http" {
				return ValidationError{Field: operationField, Message: "requires a write, execute, delete, or admin effect"}
			}
			if _, duplicate := seenOperations[operation]; duplicate {
				return ValidationError{Field: operationField, Message: "must be unique"}
			}
			seenOperations[operation] = struct{}{}
		}
		if item.Transport != "http" && len(item.HTTPMethods) > 0 {
			return ValidationError{Field: itemField + ".http_methods", Message: "is only allowed for http connectors"}
		}
		if item.Transport == "http" && len(item.HTTPMethods) == 0 {
			return ValidationError{Field: itemField + ".http_methods", Message: "must not be empty for http connectors"}
		}
		seenHTTPMethods := map[string]struct{}{}
		for methodIndex, httpMethod := range item.HTTPMethods {
			httpMethodField := fmt.Sprintf("%s.http_methods[%d]", itemField, methodIndex)
			if !validHTTPMethod(httpMethod) {
				return ValidationError{Field: httpMethodField, Message: "must be an uppercase supported HTTP method"}
			}
			if method.Effect == MethodEffectRead && !readOnlyHTTPMethod(httpMethod) {
				return ValidationError{Field: httpMethodField, Message: "must be GET, HEAD, or OPTIONS for a read effect method"}
			}
			if _, duplicate := seenHTTPMethods[httpMethod]; duplicate {
				return ValidationError{Field: httpMethodField, Message: "must be unique"}
			}
			seenHTTPMethods[httpMethod] = struct{}{}
		}
	}
	return nil
}

func validStoreKind(kind string) bool {
	return kind == "files" || kind == "kv" || kind == "sqlite"
}

func validStorageOperation(kind string, operation string) bool {
	switch kind {
	case "files":
		return operation == "read" || operation == "write" || operation == "delete" || operation == "list"
	case "kv":
		return operation == "get" || operation == "put" || operation == "delete" || operation == "list"
	case "sqlite":
		return operation == "query" || operation == "exec"
	default:
		return false
	}
}

func readOnlyStorageOperation(operation string) bool {
	switch operation {
	case "read", "list", "get", "query":
		return true
	default:
		return false
	}
}

func validNetworkOperation(transport string, operation string) bool {
	switch transport {
	case "http":
		return operation == "http" || operation == "http_stream"
	case "websocket":
		return operation == "websocket_round_trip"
	case "tcp":
		return operation == "tcp_round_trip"
	case "udp":
		return operation == "udp_round_trip"
	default:
		return false
	}
}

func validHTTPMethod(method string) bool {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		return true
	default:
		return false
	}
}

func readOnlyHTTPMethod(method string) bool {
	return method == "GET" || method == "HEAD" || method == "OPTIONS"
}

func validSurfaceKind(kind SurfaceKind) bool {
	return kind == SurfaceView || kind == SurfaceCommand || kind == SurfaceBackground
}

func validSurfaceIntent(intent SurfaceIntent) bool {
	return intent == SurfaceIntentPrimary || intent == SurfaceIntentSecondary || intent == SurfaceIntentUtility
}

func validateSurfaceIcon(icon string) error {
	if icon == "" {
		return nil
	}
	if strings.EqualFold(path.Ext(icon), ".svg") {
		return errors.New("SVG icons are not allowed")
	}
	if strings.TrimSpace(icon) != icon || strings.HasPrefix(icon, "/") || strings.ContainsAny(icon, "\\?#:\r\n\t\x00") {
		return errors.New("must reference a package-local relative raster image asset")
	}
	for _, part := range strings.Split(icon, "/") {
		if part == "" || strings.HasPrefix(part, ".") {
			return errors.New("must reference a package-local relative raster image asset")
		}
	}
	switch strings.ToLower(path.Ext(icon)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico":
		return nil
	default:
		return errors.New("must reference a package-local relative raster image asset")
	}
}

func DescriptorHashInput(m Manifest) ([]byte, error) {
	methods := append([]MethodSpec(nil), m.Methods...)
	sort.Slice(methods, func(i, j int) bool { return methods[i].Method < methods[j].Method })

	input := struct {
		SchemaVersion      string              `json:"schema_version"`
		PublisherID        string              `json:"publisher_id"`
		PluginID           string              `json:"plugin_id"`
		Version            string              `json:"version"`
		APIVersion         string              `json:"api_version"`
		UIProtocolVersion  string              `json:"ui_protocol_version"`
		CapabilityBindings []CapabilityBinding `json:"capability_bindings"`
		Methods            []MethodSpec        `json:"methods"`
		Workers            []WorkerSpec        `json:"workers"`
		Storage            *StorageSpec        `json:"storage,omitempty"`
		NetworkAccess      *NetworkAccessSpec  `json:"network_access,omitempty"`
		Settings           *SettingsSpec       `json:"settings,omitempty"`
	}{
		SchemaVersion:      m.SchemaVersion,
		PublisherID:        m.Publisher.PublisherID,
		PluginID:           m.Plugin.PluginID,
		Version:            m.Plugin.Version,
		APIVersion:         m.Plugin.APIVersion,
		UIProtocolVersion:  m.Plugin.UIProtocolVersion,
		CapabilityBindings: m.CapabilityBindings,
		Methods:            methods,
		Workers:            m.Workers,
		Storage:            m.Storage,
		NetworkAccess:      m.NetworkAccess,
		Settings:           m.Settings,
	}
	return json.Marshal(input)
}

func validEffect(effect MethodEffect) bool {
	switch effect {
	case MethodEffectRead, MethodEffectWrite, MethodEffectExecute, MethodEffectDelete, MethodEffectAdmin:
		return true
	default:
		return false
	}
}

func validExecutionMode(mode MethodExecutionMode) bool {
	switch mode {
	case MethodExecutionSync, MethodExecutionOperation, MethodExecutionSubscription:
		return true
	default:
		return false
	}
}

func validateMethodRoute(field string, route MethodRouteSpec, bindings map[string]struct{}, workers map[string]struct{}) error {
	switch route.Kind {
	case MethodRouteCapability:
		if _, ok := bindings[route.BindingID]; !ok {
			return ValidationError{Field: field + ".binding_id", Message: "must reference a declared capability binding"}
		}
		if strings.TrimSpace(route.TargetMethod) == "" {
			return ValidationError{Field: field + ".target_method", Message: "is required for capability routes"}
		}
		if strings.TrimSpace(route.WorkerID) != "" {
			return ValidationError{Field: field + ".worker_id", Message: "is only allowed for worker routes"}
		}
		if strings.TrimSpace(route.ActionID) != "" {
			return ValidationError{Field: field + ".action_id", Message: "is only allowed for core_action routes"}
		}
	case MethodRouteWorker:
		if _, ok := workers[route.WorkerID]; !ok {
			return ValidationError{Field: field + ".worker_id", Message: "must reference a declared worker"}
		}
		if strings.TrimSpace(route.BindingID) != "" {
			return ValidationError{Field: field + ".binding_id", Message: "is only allowed for capability routes"}
		}
		if strings.TrimSpace(route.TargetMethod) != "" {
			return ValidationError{Field: field + ".target_method", Message: "is only allowed for capability routes"}
		}
		if strings.TrimSpace(route.ActionID) != "" {
			return ValidationError{Field: field + ".action_id", Message: "is only allowed for core_action routes"}
		}
	case MethodRouteCoreAction:
		if strings.TrimSpace(route.ActionID) == "" {
			return ValidationError{Field: field + ".action_id", Message: "is required for core_action routes"}
		}
		if strings.TrimSpace(route.BindingID) != "" {
			return ValidationError{Field: field + ".binding_id", Message: "is only allowed for capability routes"}
		}
		if strings.TrimSpace(route.TargetMethod) != "" {
			return ValidationError{Field: field + ".target_method", Message: "is only allowed for capability routes"}
		}
		if strings.TrimSpace(route.WorkerID) != "" {
			return ValidationError{Field: field + ".worker_id", Message: "is only allowed for worker routes"}
		}
	default:
		return ValidationError{Field: field + ".kind", Message: "must be capability, worker, or core_action"}
	}
	return nil
}

func validateMethodConfirmation(field string, method MethodSpec) error {
	if method.PreflightOnly {
		if method.Effect != MethodEffectRead {
			return ValidationError{Field: field + ".effect", Message: "must be read for preflight_only methods"}
		}
		if method.Execution != MethodExecutionSync {
			return ValidationError{Field: field + ".execution", Message: "must be sync for preflight_only methods"}
		}
		if method.Dangerous {
			return ValidationError{Field: field + ".dangerous", Message: "must be false for preflight_only methods"}
		}
	}
	if method.Confirmation == nil {
		if method.Dangerous {
			return ValidationError{Field: field + ".confirmation", Message: "is required for dangerous methods"}
		}
		return nil
	}
	if !validConfirmationMode(method.Confirmation.Mode) {
		return ValidationError{Field: field + ".confirmation.mode", Message: "must be none, required, or risk_based"}
	}
	if method.Dangerous && method.Confirmation.Mode == ConfirmationNone {
		return ValidationError{Field: field + ".confirmation.mode", Message: "must be required or risk_based for dangerous methods"}
	}
	if method.PreflightOnly && method.Confirmation.Mode != ConfirmationNone {
		return ValidationError{Field: field + ".confirmation.mode", Message: "must be none for preflight_only methods"}
	}
	if method.Confirmation.PreflightMethod != nil {
		if strings.TrimSpace(*method.Confirmation.PreflightMethod) == "" {
			return ValidationError{Field: field + ".confirmation.preflight_method", Message: "must not be empty"}
		}
		if method.Confirmation.Mode == ConfirmationNone {
			return ValidationError{Field: field + ".confirmation.preflight_method", Message: "is only allowed when confirmation mode is required or risk_based"}
		}
		if !method.Confirmation.PlanHashRequired {
			return ValidationError{Field: field + ".confirmation.plan_hash_required", Message: "must be true when preflight_method is set"}
		}
	}
	seenRequestHashFields := map[string]struct{}{}
	for i, hashField := range method.Confirmation.RequestHashFields {
		if strings.TrimSpace(hashField) == "" {
			return ValidationError{Field: fmt.Sprintf("%s.confirmation.request_hash_fields[%d]", field, i), Message: "must not be empty"}
		}
		if _, ok := seenRequestHashFields[hashField]; ok {
			return ValidationError{Field: fmt.Sprintf("%s.confirmation.request_hash_fields[%d]", field, i), Message: "must be unique"}
		}
		seenRequestHashFields[hashField] = struct{}{}
	}
	return nil
}

func validateMethodCancelPolicy(field string, method MethodSpec) error {
	if method.Execution == MethodExecutionSync {
		if method.CancelPolicy == nil {
			return nil
		}
		if method.CancelPolicy.Cancelable {
			return ValidationError{Field: field + ".cancel_policy.cancelable", Message: "must be false for sync methods"}
		}
		if strings.TrimSpace(method.CancelPolicy.DisableBehavior) != "" {
			return ValidationError{Field: field + ".cancel_policy.disable_behavior", Message: "is only allowed for operation and subscription methods"}
		}
		if strings.TrimSpace(method.CancelPolicy.UninstallBehavior) != "" {
			return ValidationError{Field: field + ".cancel_policy.uninstall_behavior", Message: "is only allowed for operation and subscription methods"}
		}
		if method.CancelPolicy.AckTimeoutMS != 0 {
			return ValidationError{Field: field + ".cancel_policy.ack_timeout_ms", Message: "is only allowed for operation and subscription methods"}
		}
		return nil
	}
	if method.CancelPolicy == nil {
		return ValidationError{Field: field + ".cancel_policy", Message: "is required for operation and subscription methods"}
	}
	if !validCancelDisableBehavior(method.CancelPolicy.DisableBehavior) {
		return ValidationError{Field: field + ".cancel_policy.disable_behavior", Message: "must be cancel, orphan, or wait"}
	}
	if !validCancelUninstallBehavior(method.CancelPolicy.UninstallBehavior) {
		return ValidationError{Field: field + ".cancel_policy.uninstall_behavior", Message: "must be cancel_then_block_delete or force_cleanup_allowed"}
	}
	if method.CancelPolicy.AckTimeoutMS < 0 {
		return ValidationError{Field: field + ".cancel_policy.ack_timeout_ms", Message: "must be zero or positive"}
	}
	if method.CancelPolicy.Cancelable && method.CancelPolicy.AckTimeoutMS == 0 {
		return ValidationError{Field: field + ".cancel_policy.ack_timeout_ms", Message: "must be positive for cancelable methods"}
	}
	if !method.CancelPolicy.Cancelable && method.CancelPolicy.AckTimeoutMS != 0 {
		return ValidationError{Field: field + ".cancel_policy.ack_timeout_ms", Message: "must be zero for non-cancelable methods"}
	}
	return nil
}

func validConfirmationMode(mode ConfirmationMode) bool {
	switch mode {
	case ConfirmationNone, ConfirmationRequired, ConfirmationRiskBased:
		return true
	default:
		return false
	}
}

func validCancelDisableBehavior(behavior string) bool {
	switch behavior {
	case CancelDisableBehaviorCancel, CancelDisableBehaviorOrphan, CancelDisableBehaviorWait:
		return true
	default:
		return false
	}
}

func validCancelUninstallBehavior(behavior string) bool {
	switch behavior {
	case CancelUninstallBehaviorCancelThenBlockDelete, CancelUninstallBehaviorForceCleanupAllowed:
		return true
	default:
		return false
	}
}

func validNetworkTransport(transport string) bool {
	switch transport {
	case "http", "websocket", "tcp", "udp":
		return true
	default:
		return false
	}
}

func validSettingType(fieldType string) bool {
	switch fieldType {
	case "string", "boolean", "number", "integer", "enum", "select", "secret":
		return true
	default:
		return false
	}
}
