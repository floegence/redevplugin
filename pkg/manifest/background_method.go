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
	for _, key := range []string{"interval_ms", "max_runtime_ms"} {
		if raw, present := fields[key]; present && (bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || decoded.Strategy != BackgroundInterval) {
			return fmt.Errorf("background.%s requires an interval and a non-null integer", key)
		}
	}
	*entry = BackgroundSpec(decoded)
	return nil
}

func validateBackgroundMethod(m Manifest, methods map[string]MethodSpec) error {
	entry := m.Background
	if entry == nil {
		return nil
	}
	if entry.Strategy == BackgroundInterval {
		if !featureDeclared(m.API.RequiredFeatures, FeatureBackgroundInterval) || entry.Method == "" {
			return ValidationError{Field: "background", Message: "interval requires background.interval.v1 and an explicit method"}
		}
		if entry.IntervalMS < 1000 || entry.IntervalMS > 86400000 {
			return ValidationError{Field: "background.interval_ms", Message: "must be between 1000 and 86400000"}
		}
		if entry.MaxRuntimeMS < 1 || entry.MaxRuntimeMS > 300000 || entry.MaxRuntimeMS > entry.IntervalMS {
			return ValidationError{Field: "background.max_runtime_ms", Message: "must be between 1 and 300000 and not exceed interval_ms"}
		}
	} else if entry.IntervalMS != 0 || entry.MaxRuntimeMS != 0 {
		return ValidationError{Field: "background", Message: "interval limits require the interval strategy"}
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
	if entry.Strategy == BackgroundInterval && method.Execution != MethodExecutionSync {
		return ValidationError{Field: "background.method", Message: "interval requires synchronous execution"}
	}
	for _, worker := range m.Workers {
		if worker.WorkerID == entry.WorkerID && entry.Strategy == BackgroundInterval && worker.Mode != WorkerModeJob {
			return ValidationError{Field: "background.worker_id", Message: "interval requires a job worker"}
		}
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
