//go:build darwin || linux

package pluginpkg

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"syscall"
	"testing"

	"github.com/floegence/redevplugin/internal/performanceevidence"
)

const packagePerformanceProbeMode = "REDEVPLUGIN_PACKAGE_PERFORMANCE_PROBE"
const packagePerformanceProbeArchive = "REDEVPLUGIN_PACKAGE_PERFORMANCE_ARCHIVE"

func TestPerformancePackageOwnedMaterializationRSS(t *testing.T) {
	const samples = 3
	archivePath := t.TempDir() + "/package.rdp"
	if err := os.WriteFile(archivePath, buildPackagePerformanceArchive(t), 0o600); err != nil {
		t.Fatal(err)
	}
	owned := make([]float64, 0, samples)
	cloned := make([]float64, 0, samples)
	for range samples {
		owned = append(owned, runPackagePerformanceProbe(t, "owned", archivePath))
		cloned = append(cloned, runPackagePerformanceProbe(t, "cloned", archivePath))
	}
	ownedRSS := medianFloat64(owned)
	clonedRSS := medianFloat64(cloned)
	relative, err := performanceevidence.RelativeBasisPoints(ownedRSS, clonedRSS)
	if err != nil {
		t.Fatal(err)
	}
	if performanceevidence.EnforceThresholds() && relative > 6_500 {
		t.Fatalf("owned package peak RSS %.0f versus cloned %.0f = %.2f basis points, want <= 6500", ownedRSS, clonedRSS, relative)
	}
	if err := performanceevidence.Record(os.Getenv("REDEVPLUGIN_PERFORMANCE_MEASUREMENTS"), performanceevidence.Scenario{
		ID:          "pluginpkg.package-owned-materialization",
		Gate:        performanceevidence.Gate(),
		SampleCount: samples,
		Metrics: []performanceevidence.Metric{
			{Name: "peak_rss_relative_to_cloned", Unit: "basis_points", Observed: relative, Limit: 6_500, Comparator: "lte"},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPerformancePackageOwnedMaterializationProbe(t *testing.T) {
	mode := os.Getenv(packagePerformanceProbeMode)
	if mode == "" {
		t.Skip("package performance probe runs only in an isolated child process")
	}
	archivePath := os.Getenv(packagePerformanceProbeArchive)
	archive, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	info, err := archive.Stat()
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	pkg, err := Read(context.Background(), archive, info.Size(), DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryAssetStore()
	switch mode {
	case "owned":
		if err := store.PutOwnedPackage(context.Background(), &pkg); err != nil {
			t.Fatal(err)
		}
	case "cloned":
		cloned := clonePackageFilesForPerformanceEvidence(pkg)
		if err := store.PutOwnedPackage(context.Background(), &cloned); err != nil {
			t.Fatal(err)
		}
		runtime.KeepAlive(pkg)
	default:
		t.Fatalf("unknown package performance probe mode %q", mode)
	}
	asset, err := store.ReadAsset(context.Background(), pkg.PackageHash, "ui/assets/payload-a.bin")
	if err != nil || len(asset.Content) != 24<<20 {
		t.Fatalf("stored package probe asset bytes=%d err=%v", len(asset.Content), err)
	}
	runtime.KeepAlive(store)
}

func runPackagePerformanceProbe(t *testing.T, mode, archivePath string) float64 {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestPerformancePackageOwnedMaterializationProbe$", "-test.count=1")
	cmd.Env = append(os.Environ(), packagePerformanceProbeMode+"="+mode, packagePerformanceProbeArchive+"="+archivePath)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("package performance probe %s failed: %v\n%s", mode, err, output.String())
	}
	usage, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage)
	if !ok || usage == nil || usage.Maxrss <= 0 {
		t.Fatalf("package performance probe %s did not report max RSS", mode)
	}
	maxRSS := float64(usage.Maxrss)
	if runtime.GOOS == "linux" {
		maxRSS *= 1024
	}
	return maxRSS
}

func buildPackagePerformanceArchive(t *testing.T) []byte {
	t.Helper()
	files := map[string][]byte{
		"manifest.json":           []byte(validManifestJSON()),
		"ui/index.html":           []byte(fixtureSurfaceHTML),
		"ui/assets/app.js":        []byte("void 0;"),
		"ui/assets/payload-a.bin": packagePerformancePayload(24<<20, 1),
		"ui/assets/payload-b.bin": packagePerformancePayload(24<<20, 2),
		"ui/assets/payload-c.bin": packagePerformancePayload(24<<20, 3),
		"ui/assets/payload-d.bin": packagePerformancePayload(24<<20, 4),
	}
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, entryPath := range sortedFilePaths(files) {
		header := &zip.FileHeader{Name: entryPath, Method: zip.Deflate, Modified: deterministicModTime}
		header.SetMode(0o644)
		entry, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(files[entryPath]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func packagePerformancePayload(size int, seed uint64) []byte {
	payload := make([]byte, size)
	state := seed
	for index := 0; index < len(payload); index += 32 {
		state = state*6364136223846793005 + 1442695040888963407
		payload[index] = byte(state >> 56)
	}
	return payload
}

func clonePackageFilesForPerformanceEvidence(pkg Package) Package {
	cloned := pkg
	cloned.Files = make(map[string][]byte, len(pkg.Files))
	for path, content := range pkg.Files {
		cloned.Files[path] = append([]byte(nil), content...)
	}
	cloned.SignatureFiles = make(map[string][]byte, len(pkg.SignatureFiles))
	for path, content := range pkg.SignatureFiles {
		cloned.SignatureFiles[path] = append([]byte(nil), content...)
	}
	return cloned
}

func medianFloat64(values []float64) float64 {
	ordered := append([]float64(nil), values...)
	sort.Float64s(ordered)
	if len(ordered) == 0 {
		panic("median requires at least one value")
	}
	return ordered[len(ordered)/2]
}
