//go:build !darwin && !linux

package runtimeclient

func launchRuntimeProcess(options runtimeProcessLaunchOptions) (*runtimeProcess, error) {
	return launchPortableRuntimeProcess(options)
}

func closeRuntimePIDFD(int) error {
	return nil
}
