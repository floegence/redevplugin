package httpadapter

import (
	"fmt"
	"time"

	"github.com/floegence/redevplugin/internal/jsonvalue"
)

type wireProjectionError struct {
	path string
	err  error
}

func (e *wireProjectionError) Error() string {
	return fmt.Sprintf("project canonical JSON at %s: %v", e.path, e.err)
}

func (e *wireProjectionError) Unwrap() error {
	return e.err
}

func cloneWireJSONMap(values map[string]any) (map[string]any, error) {
	if values == nil {
		return nil, nil
	}
	if err := jsonvalue.ValidateCanonical(values); err != nil {
		return nil, &wireProjectionError{path: "$", err: err}
	}
	return cloneValidatedWireJSONMap(values, "$")
}

func cloneWireJSONValue(value any) (any, error) {
	if err := jsonvalue.ValidateCanonical(value); err != nil {
		return nil, &wireProjectionError{path: "$", err: err}
	}
	return cloneValidatedWireJSONValue(value, "$")
}

func cloneValidatedWireJSONMap(values map[string]any, path string) (map[string]any, error) {
	cloned := make(map[string]any, len(values))
	for key, item := range values {
		mapped, err := cloneValidatedWireJSONValue(item, fmt.Sprintf("%s[%q]", path, key))
		if err != nil {
			return nil, err
		}
		cloned[key] = mapped
	}
	return cloned, nil
}

func cloneValidatedWireJSONValue(value any, path string) (any, error) {
	switch typed := value.(type) {
	case nil, bool, string, float64:
		return typed, nil
	case map[string]any:
		return cloneValidatedWireJSONMap(typed, path)
	case []any:
		cloned := make([]any, len(typed))
		for index, item := range typed {
			mapped, err := cloneValidatedWireJSONValue(item, fmt.Sprintf("%s[%d]", path, index))
			if err != nil {
				return nil, err
			}
			cloned[index] = mapped
		}
		return cloned, nil
	default:
		return nil, &wireProjectionError{
			path: path,
			err:  fmt.Errorf("unsupported canonical JSON type %T", value),
		}
	}
}

func cloneWireStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneWireTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneWireString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneWireInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
