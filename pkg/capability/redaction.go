package capability

import "strings"

const DefaultRedactedValue = "[REDACTED]"

type ResponseRedactionPolicy struct {
	Replacement string
	MaxDepth    int
}

var DefaultResponseRedactionPolicy = ResponseRedactionPolicy{
	Replacement: DefaultRedactedValue,
	MaxDepth:    64,
}

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

func RedactResponseData(data any) any {
	return DefaultResponseRedactionPolicy.Redact(data)
}

func (p ResponseRedactionPolicy) Redact(data any) any {
	replacement := strings.TrimSpace(p.Replacement)
	if replacement == "" {
		replacement = DefaultRedactedValue
	}
	maxDepth := p.MaxDepth
	if maxDepth <= 0 {
		maxDepth = DefaultResponseRedactionPolicy.MaxDepth
	}
	return p.redactValue(data, redactionContext{}, replacement, 0, maxDepth)
}

func (p ResponseRedactionPolicy) redactValue(value any, ctx redactionContext, replacement string, depth int, maxDepth int) any {
	if depth > maxDepth {
		return replacement
	}

	switch v := value.(type) {
	case nil:
		return nil
	case map[string]any:
		return p.redactAnyMap(v, ctx, replacement, depth, maxDepth)
	case map[string]string:
		return p.redactStringMap(v, ctx, replacement)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = p.redactValue(item, ctx, replacement, depth+1, maxDepth)
		}
		return out
	case []string:
		out := make([]string, len(v))
		for i, item := range v {
			out[i] = p.redactString(item, ctx, replacement)
		}
		return out
	case string:
		return p.redactString(v, ctx, replacement)
	default:
		return value
	}
}

func (p ResponseRedactionPolicy) redactAnyMap(in map[string]any, ctx redactionContext, replacement string, depth int, maxDepth int) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		childCtx := childRedactionContext(ctx, key)
		switch {
		case ctx.mode == redactionModeEnv && isSensitiveEnvName(key):
			out[key] = replacement
		case ctx.mode == redactionModeLabels && isSensitiveDataKey(key):
			out[key] = replacement
		case ctx.mode == redactionModeMount && shouldRedactMountField(key, value):
			out[key] = replacement
		case isSensitiveDataKey(key):
			out[key] = replacement
		default:
			out[key] = p.redactValue(value, childCtx, replacement, depth+1, maxDepth)
		}
	}
	return out
}

func (p ResponseRedactionPolicy) redactStringMap(in map[string]string, ctx redactionContext, replacement string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		switch {
		case ctx.mode == redactionModeEnv && isSensitiveEnvName(key):
			out[key] = replacement
		case ctx.mode == redactionModeLabels && isSensitiveDataKey(key):
			out[key] = replacement
		case ctx.mode == redactionModeMount && shouldRedactMountField(key, value):
			out[key] = replacement
		case isSensitiveDataKey(key):
			out[key] = replacement
		default:
			out[key] = p.redactString(value, childRedactionContext(ctx, key), replacement)
		}
	}
	return out
}

func (p ResponseRedactionPolicy) redactString(value string, ctx redactionContext, replacement string) string {
	switch ctx.mode {
	case redactionModeEnv:
		return redactAssignmentString(value, replacement, isSensitiveEnvName)
	case redactionModeLabels:
		return redactAssignmentString(value, replacement, isSensitiveDataKey)
	case redactionModeMount:
		if isSensitiveMountPath(value) {
			return replacement
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
	case []string:
		for _, item := range v {
			if isSensitiveMountPath(item) {
				return true
			}
		}
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
	case map[string]string:
		for _, item := range v {
			if isSensitiveMountPath(item) {
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
