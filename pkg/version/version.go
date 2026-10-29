package version

import (
	"runtime/debug"
	"strings"
)

const (
	modulePath = "github.com/floegence/redevplugin/v3"
	devVersion = "0.0.0-dev"
)

var (
	goModuleVersionOverride = devVersion
	buildInfoModuleVersion  = detectBuildInfoModuleVersion
)

func CurrentPlatformVersion() string {
	version := resolvedReleaseVersion(goModuleVersionOverride)
	if version == devVersion {
		return developmentPlatformVersion
	}
	return version
}

func resolvedReleaseVersion(configured string) string {
	if configured != "" && configured != devVersion {
		return configured
	}
	if detected := buildInfoModuleVersion(); detected != "" {
		return detected
	}
	if configured == "" {
		return devVersion
	}
	return configured
}

func detectBuildInfoModuleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	return platformVersionFromBuildInfo(info)
}

func platformVersionFromBuildInfo(info *debug.BuildInfo) string {
	if info.Main.Path == modulePath {
		// Source builds may carry a VCS-derived pseudo-version or +dirty suffix.
		// VERSION-generated identity is authoritative for this executable.
		return ""
	}
	for _, dependency := range info.Deps {
		if dependency.Path != modulePath {
			continue
		}
		if version := normalizeModuleVersion(dependency.Version); version != "" {
			return version
		}
	}
	return ""
}

func normalizeModuleVersion(version string) string {
	if version == "" || version == "(devel)" {
		return ""
	}
	return strings.TrimPrefix(version, "v")
}
