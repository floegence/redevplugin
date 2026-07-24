package contracts_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/floegence/redevplugin/pkg/contracts"
)

func TestContractInventoryIncludesSyntheticRegistry(t *testing.T) {
	registry := contracts.ContractRegistry()
	if registry.SchemaVersion != "redevplugin.contract_registry.v2" || registry.RegistryVersion != "contract-registry-v2" {
		t.Fatalf("registry identity = %#v", registry)
	}
	artifacts := contracts.Artifacts()
	if len(artifacts) != 49 || len(registry.Artifacts) != len(artifacts) {
		t.Fatalf("artifact counts = %d/%d, want 49", len(artifacts), len(registry.Artifacts))
	}
	for _, artifact := range artifacts {
		if artifact.ID() == contracts.IDContractRegistry {
			t.Fatal("artifact inventory contains the synthetic registry contract")
		}
		assertContractReadable(t, artifact)
		sum := sha256.Sum256(artifact.Bytes())
		if got := hex.EncodeToString(sum[:]); got != artifact.SHA256() {
			t.Fatalf("contract %q sha256 = %s, want %s", artifact.ID(), artifact.SHA256(), got)
		}
	}
	registryContract := contracts.RegistryContract()
	if registryContract.ID() != contracts.IDContractRegistry || registryContract.Version() != "contract-registry-v2" {
		t.Fatalf("registry contract = %q/%q", registryContract.ID(), registryContract.Version())
	}
	assertContractReadable(t, registryContract)
	registrySum := sha256.Sum256(registryContract.Bytes())
	if got := hex.EncodeToString(registrySum[:]); got != registryContract.SHA256() {
		t.Fatalf("registry sha256 = %s, want %s", registryContract.SHA256(), got)
	}
	if got := string(registryContract.Bytes()); got == "" || got[len(got)-1] != '\n' {
		t.Fatal("registry contract does not expose its exact canonical document bytes")
	}
}

func TestContractSetDigestIncludesSyntheticRegistryCoordinate(t *testing.T) {
	type coordinate struct {
		ID      string `json:"id"`
		Version string `json:"version"`
		SHA256  string `json:"sha256"`
	}
	artifacts := contracts.Artifacts()
	coordinates := make([]coordinate, 0, len(artifacts)+1)
	for _, artifact := range artifacts {
		coordinates = append(coordinates, coordinate{
			ID: string(artifact.ID()), Version: artifact.Version(), SHA256: artifact.SHA256(),
		})
	}
	registry := contracts.RegistryContract()
	coordinates = append(coordinates, coordinate{
		ID: string(registry.ID()), Version: registry.Version(), SHA256: registry.SHA256(),
	})
	sort.Slice(coordinates, func(i, j int) bool { return coordinates[i].ID < coordinates[j].ID })
	canonical, err := json.Marshal(coordinates)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	if got, want := contracts.PackageSet().ContractSetSHA256, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("contract set sha256 = %s, want %s", got, want)
	}
	canonical[0] ^= 1
	tampered := sha256.Sum256(canonical)
	if contracts.PackageSet().ContractSetSHA256 == hex.EncodeToString(tampered[:]) {
		t.Fatal("contract set digest accepted tampered canonical coordinates")
	}
}

func TestContractSnapshotsAndBytesAreOwned(t *testing.T) {
	artifacts := contracts.Artifacts()
	wantFirstID := artifacts[0].ID()
	wantFirstBody := artifacts[0].Bytes()
	wantFirstRead, err := contracts.Read(wantFirstID)
	if err != nil {
		t.Fatal(err)
	}
	artifacts[0] = artifacts[1]
	wantFirstBody[0] ^= 0xff
	wantFirstRead[0] ^= 0xff
	if got := contracts.Artifacts()[0]; got.ID() != wantFirstID || string(got.Bytes()) == string(wantFirstBody) {
		t.Fatal("artifact slice or bytes share caller-mutable backing storage")
	}
	if got, err := contracts.Read(wantFirstID); err != nil || string(got) == string(wantFirstRead) {
		t.Fatal("Read() shares caller-mutable backing storage")
	}
	registryContractBody := contracts.RegistryContract().Bytes()
	registryContractBody[0] ^= 0xff
	if got := contracts.RegistryContract().Bytes(); string(got) == string(registryContractBody) {
		t.Fatal("RegistryContract().Bytes() shares caller-mutable backing storage")
	}

	registry := contracts.ContractRegistry()
	wantRegistryID := registry.Artifacts[0].ID
	registry.SchemaVersion = "mutated"
	registry.RegistryVersion = "mutated"
	registry.Artifacts[0].ID = contracts.IDContractRegistry
	registry.Artifacts[0].Path = "mutated"
	registry.Artifacts[0].Version = "mutated"
	registry.Artifacts[0].SHA256 = "mutated"
	freshRegistry := contracts.ContractRegistry()
	if freshRegistry.SchemaVersion != "redevplugin.contract_registry.v2" ||
		freshRegistry.RegistryVersion != "contract-registry-v2" ||
		freshRegistry.Artifacts[0].ID != wantRegistryID {
		t.Fatal("registry snapshot shares mutable artifact storage")
	}

	packageSet := contracts.PackageSet()
	wantNPMName := packageSet.NPMPackages[0].Name
	packageSet.SchemaVersion = "mutated"
	packageSet.PlatformVersion = "mutated"
	packageSet.GoModule.Module = "mutated"
	packageSet.GoModule.Version = "mutated"
	packageSet.NPMPackages[0].Name = "mutated"
	packageSet.RustCrates[0].Role = "mutated"
	packageSet.ContractRegistryVersion = "mutated"
	packageSet.ContractSetSHA256 = "mutated"
	if got := contracts.PackageSet(); got.SchemaVersion != "redevplugin.platform_package_set.v1" ||
		got.PlatformVersion != "0.6.11" ||
		got.GoModule.Module != "github.com/floegence/redevplugin" ||
		got.NPMPackages[0].Name != wantNPMName || got.RustCrates[0].Role != "contracts" ||
		got.ContractRegistryVersion != "contract-registry-v2" || len(got.ContractSetSHA256) != 64 {
		t.Fatal("package set snapshot shares mutable coordinate storage")
	}
}

func TestHostDoesNotEmbedContractsPackageTransitively(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	for _, packagePath := range []string{"./pkg/host", "./pkg/httpadapter"} {
		command := exec.Command("go", "list", "-deps", packagePath)
		command.Dir = root
		command.Env = append(os.Environ(), "GOWORK=off")
		output, err := command.Output()
		if err != nil {
			t.Fatal(err)
		}
		for _, dependency := range strings.Fields(string(output)) {
			if dependency == "github.com/floegence/redevplugin/pkg/contracts" {
				t.Fatalf("%s transitively embeds the full contract body package", packagePath)
			}
		}
	}
}

func TestContractReadAndOpenDoNotDependOnWorkingDirectory(t *testing.T) {
	registryBytes, err := contracts.Read(contracts.IDContractRegistry)
	if err != nil {
		t.Fatal(err)
	}
	oldWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	t.Cleanup(func() { _ = os.Chdir(oldWorkingDirectory) })
	for _, id := range []contracts.ID{contracts.IDContractRegistry, contracts.Artifacts()[0].ID()} {
		if got, err := contracts.Read(id); err != nil || len(got) == 0 {
			t.Fatalf("Read(%q) after chdir = %q, %v", id, got, err)
		}
	}
	file, err := contracts.Open(contracts.IDContractRegistry)
	if err != nil {
		t.Fatal(err)
	}
	if _, mutable := file.(interface{ Reset(string) }); mutable {
		t.Fatal("Open() exposes a caller-mutable Reset method")
	}
	defer file.Close()
	opened, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != string(registryBytes) {
		t.Fatal("Open() returned different bytes from Read()")
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() || info.Name() != "contract-registry" || info.Size() != int64(len(registryBytes)) {
		t.Fatalf("Open() file info = %#v", info)
	}
}

func TestPublicContractIDNamesPreserveGoInitialisms(t *testing.T) {
	for id, want := range map[contracts.ID]string{
		contracts.IDPluginPlatformOpenAPI: "plugin-platform-openapi",
		contracts.IDRustIPCSchema:         "rust-ipc-schema",
		contracts.IDWASMWorkerSchema:      "wasm-worker-schema",
	} {
		if string(id) != want {
			t.Fatalf("contract ID constant = %q, want %q", id, want)
		}
	}
}

func TestUnknownContractIDReturnsTypedError(t *testing.T) {
	unknown := contracts.ID("unknown-contract")
	for _, err := range []error{
		func() error { _, err := contracts.Read(unknown); return err }(),
		func() error { _, err := contracts.Open(unknown); return err }(),
	} {
		if !errors.Is(err, contracts.ErrUnknownID) {
			t.Fatalf("error = %v, want ErrUnknownID", err)
		}
		var typed *contracts.UnknownIDError
		if !errors.As(err, &typed) || typed.ID != unknown {
			t.Fatalf("error = %#v, want typed unknown ID", err)
		}
	}
}

func TestContractReadsAreRaceSafe(t *testing.T) {
	var wait sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 100; iteration++ {
				artifacts := contracts.Artifacts()
				body := artifacts[iteration%len(artifacts)].Bytes()
				body[0] ^= byte(iteration)
				registry := contracts.ContractRegistry()
				registry.Artifacts[0].Path = filepath.Join("mutated", "path")
				packageSet := contracts.PackageSet()
				packageSet.RustCrates[0].Name = "mutated"
				registryBody := contracts.RegistryContract().Bytes()
				registryBody[0] ^= byte(iteration)
			}
		}()
	}
	wait.Wait()
	if contracts.PackageSet().RustCrates[0].Name != "redevplugin-contracts" {
		t.Fatal("concurrent caller mutation changed the embedded package set")
	}
}

func assertContractReadable(t *testing.T, contract contracts.Contract) {
	t.Helper()
	if contract.ID() == "" || contract.Version() == "" || len(contract.SHA256()) != 64 || len(contract.Bytes()) == 0 {
		t.Fatalf("invalid contract metadata for %q", contract.ID())
	}
	read, err := contracts.Read(contract.ID())
	if err != nil {
		t.Fatal(err)
	}
	if string(read) != string(contract.Bytes()) {
		t.Fatalf("Read(%q) differs from Contract.Bytes()", contract.ID())
	}
	file, err := contracts.Open(contract.ID())
	if err != nil {
		t.Fatal(err)
	}
	opened, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || string(opened) != string(read) {
		t.Fatalf("Open(%q) differs from Read(): read=%v close=%v", contract.ID(), readErr, closeErr)
	}
}
