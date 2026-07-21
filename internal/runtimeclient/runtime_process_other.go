//go:build !linux

package runtimeclient

func launchRuntimeProcess(options runtimeProcessLaunchOptions) (*runtimeProcess, error) {
	return launchLegacyRuntimeProcess(options)
}

func closeRuntimePIDFD(int) error {
	return nil
}
