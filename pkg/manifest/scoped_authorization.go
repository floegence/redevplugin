package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// WorkerPermissionIDs returns the explicit method ceiling when present. An
// absent declaration preserves the published package-wide permission ceiling.
func (m Manifest) WorkerPermissionIDs(method MethodSpec) []PermissionID {
	if method.Permissions != nil {
		return append([]PermissionID{}, method.Permissions...)
	}
	return m.PermissionIDs()
}

func validateScopedAuthorization(m Manifest) error {
	declared := map[string]bool{}
	for _, method := range m.Methods {
		declared[method.Method] = true
	}
	for i, method := range m.Methods {
		if method.Permissions == nil {
			continue
		}
		field := fmt.Sprintf("methods[%d].permissions", i)
		if !featureDeclared(m.API.RequiredFeatures, FeatureScopedAuthorization) {
			return ValidationError{Field: field, Message: "requires authorization.scoped.v1"}
		}
		if method.Route.Kind != MethodRouteWorker {
			return ValidationError{Field: field, Message: "is only allowed for worker routes"}
		}
		if _, err := normalizePermissions(method.Permissions); err != nil {
			return ValidationError{Field: field, Message: err.Error()}
		}
		for _, permission := range method.Permissions {
			if !permissionDeclared(m.Permissions, permission) {
				return ValidationError{Field: field, Message: "must be a subset of package permissions"}
			}
		}
		if access := method.BrokerAccess; access != nil {
			if len(access.Process) > 0 && !permissionDeclared(method.Permissions, PermissionProcessLocal) {
				return ValidationError{Field: field, Message: "must include process.local for process broker access"}
			}
			if len(access.Network) > 0 && !permissionDeclared(method.Permissions, PermissionNetworkClient) {
				return ValidationError{Field: field, Message: "must include network.client for connector broker access"}
			}
		}
	}
	for i, surface := range m.Surfaces {
		if surface.RequiredMethods == nil {
			continue
		}
		field := fmt.Sprintf("surfaces[%d].required_methods", i)
		if !featureDeclared(m.API.RequiredFeatures, FeatureScopedAuthorization) {
			return ValidationError{Field: field, Message: "requires authorization.scoped.v1"}
		}
		seen := map[string]bool{}
		for _, method := range surface.RequiredMethods {
			if !declared[method] || seen[method] {
				return ValidationError{Field: field, Message: "must contain unique declared methods"}
			}
			seen[method] = true
		}
	}
	return nil
}

// PermissionSet distinguishes an absent package ceiling from an explicit empty ceiling.
type PermissionSet []PermissionID

func (values *PermissionSet) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("permissions must be an array, not null")
	}
	var decoded []PermissionID
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*values = decoded
	return nil
}

// MethodNames lists startup requirements while preserving an explicitly empty list.
type MethodNames []string

func (values *MethodNames) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("required_methods must be an array, not null")
	}
	var decoded []string
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*values = decoded
	return nil
}
