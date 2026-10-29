package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func (entry *BackgroundSpec) UnmarshalJSON(raw []byte) error {
	type backgroundWire BackgroundSpec
	var decoded backgroundWire
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if _, present := fields["method"]; present && decoded.Method == "" {
		return fmt.Errorf("background.method must be a non-empty string")
	}
	if _, present := fields["params"]; present && decoded.Params == nil {
		return fmt.Errorf("background.params must be an object")
	}
	*entry = BackgroundSpec(decoded)
	return nil
}

func validateBackgroundMethod(m Manifest, methods map[string]MethodSpec) error {
	entry := m.Background
	if entry == nil {
		return nil
	}
	if entry.Method == "" {
		if entry.Params != nil {
			return ValidationError{Field: "background.params", Message: "requires an explicit method"}
		}
		return nil
	}
	if !featureDeclared(m.API.RequiredFeatures, FeatureBackgroundMethod) {
		return ValidationError{Field: "background.method", Message: "requires background.method.v1"}
	}
	method, ok := methods[entry.Method]
	if !ok || method.Route.Kind != MethodRouteWorker || method.Route.WorkerID != entry.WorkerID {
		return ValidationError{Field: "background.method", Message: "must reference a method on the declared background worker"}
	}
	for _, worker := range m.Workers {
		if worker.WorkerID == entry.WorkerID && worker.Scope != "environment" {
			return ValidationError{Field: "background.worker_id", Message: "must use environment scope"}
		}
	}
	if method.PreflightOnly || method.Dangerous || (method.Confirmation != nil && method.Confirmation.Mode != ConfirmationNone) {
		return ValidationError{Field: "background.method", Message: "must not require interactive confirmation or be preflight-only"}
	}
	schemas, err := CompileMethodSchemas(method)
	if err != nil {
		return err
	}
	if err := schemas.ValidateRequest(entry.Params); err != nil {
		return ValidationError{Field: "background.params", Message: "must satisfy the declared method request schema"}
	}
	return nil
}
