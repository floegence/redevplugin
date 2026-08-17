package version

import "testing"

func TestCurrentPlatformVersionUsesReleaseOrSourceVersion(t *testing.T) {
	originalGoVersion := goModuleVersionOverride
	originalDetector := buildInfoModuleVersion
	t.Cleanup(func() {
		goModuleVersionOverride = originalGoVersion
		buildInfoModuleVersion = originalDetector
	})
	buildInfoModuleVersion = func() string { return "" }

	goModuleVersionOverride = "3.1.2"
	if got := CurrentPlatformVersion(); got != "3.1.2" {
		t.Fatalf("release version = %q, want 3.1.2", got)
	}
	goModuleVersionOverride = devVersion
	if got := CurrentPlatformVersion(); got != developmentPlatformVersion {
		t.Fatalf("development version = %q, want %q", got, developmentPlatformVersion)
	}
}

func TestCurrentPlatformVersionUsesBuildInfo(t *testing.T) {
	originalGoVersion := goModuleVersionOverride
	originalDetector := buildInfoModuleVersion
	t.Cleanup(func() {
		goModuleVersionOverride = originalGoVersion
		buildInfoModuleVersion = originalDetector
	})
	goModuleVersionOverride = devVersion
	buildInfoModuleVersion = func() string { return "3.2.1" }
	if got := CurrentPlatformVersion(); got != "3.2.1" {
		t.Fatalf("build info version = %q, want 3.2.1", got)
	}
}

func TestNormalizeModuleVersion(t *testing.T) {
	for input, want := range map[string]string{
		"v3.0.0":  "3.0.0",
		"3.0.0":   "3.0.0",
		"(devel)": "",
		"":        "",
	} {
		if got := normalizeModuleVersion(input); got != want {
			t.Errorf("normalizeModuleVersion(%q) = %q, want %q", input, got, want)
		}
	}
}
