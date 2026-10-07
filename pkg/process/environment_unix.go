//go:build !windows

package process

func normalizeEnvironmentKey(key string) string {
	return key
}
