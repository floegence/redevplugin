package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

type Manifest struct {
	PluginID     string              `json:"plugin_id"`
	Publisher    Publisher           `json:"publisher"`
	Version      string              `json:"version"`
	DisplayName  string              `json:"display_name"`
	Redeven      RuntimeConstraint   `json:"redeven"`
	UI           UISpec              `json:"ui"`
	Backend      BackendSpec         `json:"backend"`
	Capabilities []CapabilityBinding `json:"capabilities,omitempty"`
	Methods      []MethodSpec        `json:"methods,omitempty"`
	Surfaces     []SurfaceSpec       `json:"surfaces,omitempty"`
	Settings     []SettingFieldSpec  `json:"settings,omitempty"`
	Intents      []IntentSpec        `json:"intents,omitempty"`
}

type Publisher struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name,omitempty"`
}

type RuntimeConstraint struct {
	APIVersion        string `json:"api_version"`
	MinRuntimeVersion string `json:"min_runtime_version"`
}

type UISpec struct {
	Entrypoint string      `json:"entrypoint"`
	Sandbox    SandboxSpec `json:"sandbox"`
}

type SandboxSpec struct {
	Tokens []string `json:"tokens"`
}

type BackendKind string

const (
	BackendNone BackendKind = "none"
	BackendWASM BackendKind = "wasm"
)

type BackendSpec struct {
	Kind BackendKind `json:"kind"`
	Path string      `json:"path,omitempty"`
}

type CapabilityBinding struct {
	BindingID            string `json:"binding_id"`
	CapabilityID         string `json:"capability_id"`
	MinCapabilityVersion string `json:"min_capability_version"`
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
	MethodExecutionSync      MethodExecutionMode = "sync"
	MethodExecutionOperation MethodExecutionMode = "operation"
	MethodExecutionStream    MethodExecutionMode = "stream"
)

type MethodRouteKind string

const (
	MethodRouteCapability MethodRouteKind = "capability"
	MethodRouteWorker     MethodRouteKind = "worker"
)

type MethodRouteSpec struct {
	Kind       MethodRouteKind `json:"kind"`
	BindingID  string          `json:"binding_id,omitempty"`
	WorkerFunc string          `json:"worker_func,omitempty"`
}

type MethodSpec struct {
	Name          string              `json:"name"`
	Effect        MethodEffect        `json:"effect"`
	ExecutionMode MethodExecutionMode `json:"execution_mode"`
	Dangerous     bool                `json:"dangerous,omitempty"`
	Route         MethodRouteSpec     `json:"route"`
}

type SurfaceKind string

const (
	SurfaceActivity  SurfaceKind = "activity"
	SurfaceWorkbench SurfaceKind = "workbench_widget"
	SurfaceSettings  SurfaceKind = "settings_section"
)

type SurfaceSpec struct {
	SurfaceID string      `json:"surface_id"`
	Kind      SurfaceKind `json:"kind"`
	Label     string      `json:"label"`
	Method    string      `json:"method,omitempty"`
}

type SettingFieldSpec struct {
	Key       string   `json:"key"`
	Type      string   `json:"type"`
	Label     string   `json:"label"`
	Scope     string   `json:"scope"`
	SecretRef string   `json:"secret_ref,omitempty"`
	Options   []string `json:"options,omitempty"`
}

type IntentSpec struct {
	IntentID string `json:"intent_id"`
	Method   string `json:"method"`
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
	if decoder.More() {
		return Manifest{}, errors.New("manifest contains trailing JSON values")
	}
	return m, Validate(m)
}

func Validate(m Manifest) error {
	if strings.TrimSpace(m.PluginID) == "" {
		return ValidationError{Field: "plugin_id", Message: "is required"}
	}
	if strings.TrimSpace(m.Publisher.ID) == "" {
		return ValidationError{Field: "publisher.id", Message: "is required"}
	}
	if strings.TrimSpace(m.Version) == "" {
		return ValidationError{Field: "version", Message: "is required"}
	}
	if m.Redeven.APIVersion != "plugin-v1" {
		return ValidationError{Field: "redeven.api_version", Message: "must be plugin-v1"}
	}
	if strings.TrimSpace(m.UI.Entrypoint) == "" {
		return ValidationError{Field: "ui.entrypoint", Message: "is required"}
	}
	for _, token := range m.UI.Sandbox.Tokens {
		if token != "allow-scripts" {
			return ValidationError{Field: "ui.sandbox.tokens", Message: "only allow-scripts may be declared"}
		}
	}
	if m.Backend.Kind != BackendNone && m.Backend.Kind != BackendWASM {
		return ValidationError{Field: "backend.kind", Message: "must be none or wasm"}
	}
	if m.Backend.Kind == BackendWASM && strings.TrimSpace(m.Backend.Path) == "" {
		return ValidationError{Field: "backend.path", Message: "is required for wasm backend"}
	}

	bindings := map[string]struct{}{}
	for i, binding := range m.Capabilities {
		if binding.BindingID == "" {
			return ValidationError{Field: fmt.Sprintf("capabilities[%d].binding_id", i), Message: "is required"}
		}
		if _, ok := bindings[binding.BindingID]; ok {
			return ValidationError{Field: fmt.Sprintf("capabilities[%d].binding_id", i), Message: "must be unique"}
		}
		bindings[binding.BindingID] = struct{}{}
	}

	methods := map[string]MethodSpec{}
	for i, method := range m.Methods {
		if method.Name == "" {
			return ValidationError{Field: fmt.Sprintf("methods[%d].name", i), Message: "is required"}
		}
		if _, ok := methods[method.Name]; ok {
			return ValidationError{Field: fmt.Sprintf("methods[%d].name", i), Message: "must be unique"}
		}
		if !validEffect(method.Effect) {
			return ValidationError{Field: fmt.Sprintf("methods[%d].effect", i), Message: "is invalid"}
		}
		if !validExecutionMode(method.ExecutionMode) {
			return ValidationError{Field: fmt.Sprintf("methods[%d].execution_mode", i), Message: "is invalid"}
		}
		if method.Route.Kind != MethodRouteCapability && method.Route.Kind != MethodRouteWorker {
			return ValidationError{Field: fmt.Sprintf("methods[%d].route.kind", i), Message: "must be capability or worker"}
		}
		if method.Route.Kind == MethodRouteCapability {
			if _, ok := bindings[method.Route.BindingID]; !ok {
				return ValidationError{Field: fmt.Sprintf("methods[%d].route.binding_id", i), Message: "must reference a declared capability binding"}
			}
		}
		methods[method.Name] = method
	}

	surfaces := map[string]struct{}{}
	for i, surface := range m.Surfaces {
		key := string(surface.Kind) + ":" + surface.SurfaceID
		if _, ok := surfaces[key]; ok {
			return ValidationError{Field: fmt.Sprintf("surfaces[%d].surface_id", i), Message: "must be unique for the same surface kind"}
		}
		surfaces[key] = struct{}{}
		if surface.Method != "" {
			if _, ok := methods[surface.Method]; !ok {
				return ValidationError{Field: fmt.Sprintf("surfaces[%d].method", i), Message: "must reference a declared method"}
			}
		}
	}

	for i, intent := range m.Intents {
		if _, ok := methods[intent.Method]; !ok {
			return ValidationError{Field: fmt.Sprintf("intents[%d].method", i), Message: "must reference a declared method"}
		}
	}

	return nil
}

func DescriptorHashInput(m Manifest) ([]byte, error) {
	methods := append([]MethodSpec(nil), m.Methods...)
	sort.Slice(methods, func(i, j int) bool { return methods[i].Name < methods[j].Name })

	input := struct {
		PluginID    string       `json:"plugin_id"`
		Version     string       `json:"version"`
		APIVersion  string       `json:"api_version"`
		Methods     []MethodSpec `json:"methods"`
		BackendKind BackendKind  `json:"backend_kind"`
	}{
		PluginID:    m.PluginID,
		Version:     m.Version,
		APIVersion:  m.Redeven.APIVersion,
		Methods:     methods,
		BackendKind: m.Backend.Kind,
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
	case MethodExecutionSync, MethodExecutionOperation, MethodExecutionStream:
		return true
	default:
		return false
	}
}
