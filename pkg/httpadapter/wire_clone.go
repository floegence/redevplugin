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
	cloned, err := jsonvalue.CloneCanonicalMap(values)
	if err != nil {
		return nil, &wireProjectionError{path: "$", err: err}
	}
	return cloned, nil
}

func cloneWireJSONValue(value any) (any, error) {
	cloned, err := jsonvalue.CloneCanonical(value)
	if err != nil {
		return nil, &wireProjectionError{path: "$", err: err}
	}
	return cloned, nil
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
