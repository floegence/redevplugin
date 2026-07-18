package executionbinding

import (
	"encoding/json"
	"fmt"

	"github.com/floegence/redevplugin/pkg/capability"
)

// CloneTrusted returns an independently owned snapshot of a binding that has
// already passed capability.CloneExecutionBinding and remains store-owned.
func CloneTrusted(binding capability.ExecutionBinding) capability.ExecutionBinding {
	binding.Target.Fields = cloneTrustedCanonicalMap(binding.Target.Fields)
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
	return binding
}

func cloneTrustedCanonicalMap(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	cloned := make(map[string]any, len(value))
	for key, item := range value {
		cloned[key] = cloneTrustedCanonicalValue(item)
	}
	return cloned
}

func cloneTrustedCanonicalValue(value any) any {
	switch typed := value.(type) {
	case nil, bool, float64, json.Number, string:
		return typed
	case []any:
		if typed == nil {
			return []any(nil)
		}
		cloned := make([]any, len(typed))
		for index, item := range typed {
			cloned[index] = cloneTrustedCanonicalValue(item)
		}
		return cloned
	case map[string]any:
		return cloneTrustedCanonicalMap(typed)
	default:
		panic(fmt.Sprintf("trusted execution binding contains non-canonical JSON type %T", value))
	}
}
