package capability

import (
	"fmt"
	"strings"

	"github.com/floegence/redevplugin/internal/jsonvalue"
)

// ResponseRedactedValue is the only wire value used to replace sensitive response data.
const ResponseRedactedValue = "[REDACTED]"

type redactionMode int

const (
	redactionModeDefault redactionMode = iota
	redactionModeEnv
	redactionModeLabels
	redactionModeMount
)

type redactionContext struct {
	mode redactionMode
}

// PrepareResponseData creates and redacts the bounded JSON value that may leave an adapter boundary.
func PrepareResponseData(data any) (any, error) {
	normalized, err := jsonvalue.Normalize(data)
	if err != nil {
		return nil, fmt.Errorf("prepare capability response: %w", err)
	}
	redacted := redactJSONValue(normalized, redactionContext{})
	if err := jsonvalue.ValidateCanonical(redacted); err != nil {
		return nil, fmt.Errorf("prepare capability response: %w", err)
	}
	return redacted, nil
}

func redactJSONValue(value any, ctx redactionContext) any {
	switch v := value.(type) {
	case nil:
		return nil
	case map[string]any:
		return redactJSONMap(v, ctx)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = redactJSONValue(item, ctx)
		}
		return out
	case string:
		return redactString(v, ctx)
	default:
		return value
	}
}

func redactJSONMap(in map[string]any, ctx redactionContext) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		childCtx := childRedactionContext(ctx, key)
		switch {
		case ctx.mode == redactionModeEnv && isSensitiveEnvName(key):
			out[key] = ResponseRedactedValue
		case ctx.mode == redactionModeLabels && isSensitiveDataKey(key):
			out[key] = ResponseRedactedValue
		case ctx.mode == redactionModeMount && shouldRedactMountField(key, value):
			out[key] = ResponseRedactedValue
		case isSensitiveDataKey(key):
			out[key] = ResponseRedactedValue
		default:
			out[key] = redactJSONValue(value, childCtx)
		}
	}
	return out
}

func redactString(value string, ctx redactionContext) string {
	switch ctx.mode {
	case redactionModeEnv:
		return redactAssignmentString(value, ResponseRedactedValue, isSensitiveEnvName)
	case redactionModeLabels:
		return redactAssignmentString(value, ResponseRedactedValue, isSensitiveDataKey)
	case redactionModeMount:
		if isSensitiveMountPath(value) {
			return ResponseRedactedValue
		}
	}
	return value
}

func childRedactionContext(parent redactionContext, key string) redactionContext {
	normalized := normalizeRedactionKey(key)
	switch normalized {
	case "env", "envvars", "environment", "environmentvariables":
		return redactionContext{mode: redactionModeEnv}
	case "label", "labels", "containerlabels":
		return redactionContext{mode: redactionModeLabels}
	case "mount", "mounts", "volume", "volumes", "bind", "binds", "volumemounts":
		return redactionContext{mode: redactionModeMount}
	default:
		return parent
	}
}

func redactAssignmentString(value string, replacement string, sensitiveKey func(string) bool) string {
	name, _, ok := strings.Cut(value, "=")
	if !ok || !sensitiveKey(name) {
		return value
	}
	return name + "=" + replacement
}

func isSensitiveDataKey(key string) bool {
	normalized := normalizeRedactionKey(key)
	if normalized == "" || isSafeReferenceKey(normalized) {
		return false
	}
	if normalized == "envfile" || normalized == "envfiles" {
		return true
	}
	for _, marker := range []string{
		"password",
		"passwd",
		"secret",
		"credential",
		"credentials",
		"token",
		"bearer",
		"authorization",
		"privatekey",
		"sshkey",
		"apikey",
		"accesskey",
		"cookie",
		"sessioncookie",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func isSensitiveEnvName(name string) bool {
	return isSensitiveDataKey(name)
}

func shouldRedactMountField(key string, value any) bool {
	normalized := normalizeRedactionKey(key)
	if isSensitiveDataKey(key) {
		return true
	}
	switch normalized {
	case "source", "src", "hostpath", "path", "target", "destination", "device", "envfile", "envfiles":
		return valueContainsSensitiveMountPath(value)
	default:
		return false
	}
}

func valueContainsSensitiveMountPath(value any) bool {
	switch v := value.(type) {
	case string:
		return isSensitiveMountPath(v)
	case []any:
		for _, item := range v {
			if valueContainsSensitiveMountPath(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range v {
			if valueContainsSensitiveMountPath(item) {
				return true
			}
		}
	}
	return false
}

func isSensitiveMountPath(path string) bool {
	normalized := strings.ToLower(strings.TrimSpace(path))
	if normalized == "" {
		return false
	}
	for _, marker := range []string{
		"/run/secrets",
		"/var/run/secrets",
		"/.ssh",
		"/.kube/config",
		"/.docker/config.json",
		"id_rsa",
		"id_ed25519",
		"secret",
		"token",
		"credential",
		"password",
		"passwd",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func isSafeReferenceKey(normalized string) bool {
	for _, suffix := range []string{"id", "ids", "ref", "refs", "name", "names", "hash", "sha256", "digest", "fingerprint"} {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}

func normalizeRedactionKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	var b strings.Builder
	for _, r := range key {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
