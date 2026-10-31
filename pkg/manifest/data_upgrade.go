package manifest

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/floegence/redevplugin/v3/pkg/version"
)

// DataUpgradeSpec admits exact predecessor versions and data shapes. The output
// shape is always this package's settings and storage declaration.
type DataUpgradeSpec struct {
	From         []DataUpgradePredecessor `json:"from"`
	Method       string                   `json:"method"`
	MaxBytes     int64                    `json:"max_bytes"`
	MaxRuntimeMS int                      `json:"max_runtime_ms"`
}

type DataUpgradePredecessor struct {
	Version     string `json:"version"`
	ShapeSHA256 string `json:"shape_sha256"`
}

func (m Manifest) IsDataUpgradeMethod(name string) bool {
	return m.DataUpgrade != nil && m.DataUpgrade.Method == name
}

func validateDataUpgrade(m Manifest, methods map[string]MethodSpec) error {
	entry := m.DataUpgrade
	if entry == nil {
		return nil
	}
	fail := func(field, message string) error {
		return ValidationError{Field: "data_upgrade." + field, Message: message}
	}
	if !featureDeclared(m.API.RequiredFeatures, FeatureDataUpgrade) {
		return fail("method", "requires data.upgrade.v1")
	}
	if len(entry.From) == 0 || len(entry.From) > 32 {
		return fail("from", "must contain 1-32 exact predecessors")
	}
	seen := map[string]bool{}
	for i, previous := range entry.From {
		if _, err := version.ParseSemVer(previous.Version); err != nil || previous.Version == m.Version() || seen[previous.Version] {
			return fail(fmt.Sprintf("from[%d].version", i), "must be a unique, different semantic version")
		}
		seen[previous.Version] = true
		raw, err := hex.DecodeString(previous.ShapeSHA256)
		if err != nil || len(raw) != 32 || strings.ToLower(previous.ShapeSHA256) != previous.ShapeSHA256 {
			return fail(fmt.Sprintf("from[%d].shape_sha256", i), "must be a lowercase SHA-256 digest")
		}
	}
	if entry.MaxBytes <= 0 || entry.MaxBytes > 4<<30 {
		return fail("max_bytes", "must be between 1 and 4294967296")
	}
	if entry.MaxRuntimeMS <= 0 || entry.MaxRuntimeMS > 300000 {
		return fail("max_runtime_ms", "must be between 1 and 300000")
	}
	method, ok := methods[entry.Method]
	if !ok || method.Route.Kind != MethodRouteWorker || method.Effect != MethodEffectWrite || method.Execution != MethodExecutionSync {
		return fail("method", "must reference a synchronous write Worker method")
	}
	if method.PreflightOnly || method.Dangerous || method.Confirmation != nil && method.Confirmation.Mode != ConfirmationNone {
		return fail("method", "must not require a separate interactive confirmation")
	}
	if method.BrokerAccess != nil && (len(method.BrokerAccess.Storage)+len(method.BrokerAccess.Network)+len(method.BrokerAccess.Process) != 0) || len(m.WorkerPermissionIDs(method)) != 0 {
		return fail("method", "uses only the isolated upgrade data API without ordinary broker access or permissions")
	}
	for _, worker := range m.Workers {
		if worker.WorkerID == method.Route.WorkerID && (worker.Mode != WorkerModeJob || worker.Scope != "environment") {
			return fail("method", "requires an environment-scoped job Worker")
		}
	}
	if m.Background != nil && m.Background.Method == entry.Method {
		return fail("method", "must not be a background entry")
	}
	for _, intent := range m.Intents {
		if intent.Method == entry.Method {
			return fail("method", "must not be a user intent")
		}
	}
	for _, surface := range m.Surfaces {
		for _, required := range surface.RequiredMethods {
			if required == entry.Method {
				return fail("method", "must not be a surface startup requirement")
			}
		}
	}
	schemas, err := CompileMethodSchemas(method)
	if err != nil {
		return err
	}
	for _, scope := range []string{"environment", "user"} {
		for _, predecessor := range entry.From {
			if err := schemas.ValidateRequest(map[string]any{"from_version": predecessor.Version, "to_version": m.Version(), "scope": scope}); err != nil {
				return fail("method", "request schema must accept from_version, to_version and scope")
			}
		}
	}
	return nil
}
