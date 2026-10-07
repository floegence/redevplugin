//go:build windows

package process

import "strings"

func normalizeEnvironmentKey(key string) string {
	return strings.ToUpper(key)
}
