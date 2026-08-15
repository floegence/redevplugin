package registry

import (
	"context"
	"database/sql"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v2/pkg/execution"
	"github.com/floegence/redevplugin/v2/pkg/mutation"
	"github.com/floegence/redevplugin/v2/pkg/releasepublisher"
)

func TestRegistrySourceHasNoReleaseInstallStoreAuthority(t *testing.T) {
	packages, err := parser.ParseDir(token.NewFileSet(), ".", func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg := packages["registry"]
	if pkg == nil {
		t.Fatal("registry package source not found")
	}
	for filename, file := range pkg.Files {
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.BasicLit:
				if value.Kind == token.STRING {
					literal, unquoteErr := strconv.Unquote(value.Value)
					if unquoteErr == nil && strings.Contains(literal, "release_install_operations") {
						t.Errorf("%s contains active legacy release-install table SQL", filename)
					}
				}
			case *ast.TypeSpec:
				if value.Name.Name == "ReleaseInstallOperationStore" {
					t.Errorf("%s exports the retired release-install store authority", filename)
				}
			case *ast.FuncDecl:
				if value.Recv == nil || len(value.Recv.List) != 1 {
					break
				}
				receiver := value.Recv.List[0].Type
				if pointer, ok := receiver.(*ast.StarExpr); ok {
					receiver = pointer.X
				}
				ident, ok := receiver.(*ast.Ident)
				if !ok || (ident.Name != "MemoryStore" && ident.Name != "SQLiteStore") {
					break
				}
				for _, retired := range []string{"StartReleaseInstallOperation", "UpdateReleaseInstallOperation", "GetReleaseInstallOperation", "GetReleaseInstallOperationByRequest", "ListReleaseInstallOperations"} {
					if value.Name.Name == retired {
						t.Errorf("%s declares retired %s.%s", filename, ident.Name, retired)
					}
				}
			}
			return true
		})
	}
}

func TestReleaseInstallPayloadHasNoMirroredExecutionState(t *testing.T) {
	typeOf := reflect.TypeOf(ReleaseInstallOperation{})
	for _, retired := range []string{"OperationID", "Status", "Revision", "CreatedAt", "UpdatedAt", "TerminalAt"} {
		if _, ok := typeOf.FieldByName(retired); ok {
			t.Errorf("ReleaseInstallOperation still mirrors Execution.%s", retired)
		}
	}
}

func TestSQLiteRegistryDoesNotOwnReleaseInstallLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := NewSQLiteStore(registryTestContext(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	for _, phase := range []string{"fresh", "reopened"} {
		t.Run(phase, func(t *testing.T) {
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var count int
			if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='release_install_operations'`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatal("registry SQLite still owns release_install_operations; controlstore ExecutionView must be the only lifecycle authority")
			}
		})
		if phase == "fresh" {
			reopened, err := NewSQLiteStore(registryTestContext(), path)
			if err != nil {
				t.Fatal(err)
			}
			if err := reopened.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestReleaseInstallExecutionPayloadProgressAndTerminalCAS(t *testing.T) {
	req := releaseInstallExecutionRequest(time.Date(2026, 8, 5, 1, 2, 3, 0, time.UTC))
	created, err := PrepareReleaseInstallOperation(req)
	if err != nil {
		t.Fatal(err)
	}
	if created.Execution.Status != execution.StatusRunning || created.MutationOutcome != mutation.OutcomeNotCommitted || created.Execution.Cursor != 0 {
		t.Fatalf("created payload = %#v", created)
	}
	running, err := ApplyReleaseInstallOperationUpdate(created, UpdateReleaseInstallOperationRequest{
		ExecutionID: created.Execution.ID, ExpectedCursor: created.Execution.Cursor,
		Status: execution.StatusRunning, Phase: "download_package",
		Progress: ReleaseInstallProgress{Kind: ReleaseInstallProgressBytes, Completed: 262144, Total: 524288},
		Attempt:  2, RetryAfterMS: 250, MutationOutcome: mutation.OutcomeNotCommitted,
		Activation: created.Activation, Now: req.Now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if running.Execution.Cursor != 0 || running.Progress.Completed != 262144 || running.Attempt != 2 || running.RetryAfterMS != 250 {
		t.Fatalf("running payload = %#v", running)
	}
	failed, err := ApplyReleaseInstallOperationUpdate(running, UpdateReleaseInstallOperationRequest{
		ExecutionID: running.Execution.ID, ExpectedCursor: running.Execution.Cursor,
		Status: execution.StatusFailed, Phase: "failed", Progress: ReleaseInstallProgress{Kind: ReleaseInstallProgressIndeterminate},
		Attempt: 2, MutationOutcome: mutation.OutcomeNotCommitted,
		Failure: &ReleaseInstallFailure{Code: "PLUGIN_INSTALL_INTERRUPTED", Retryable: true}, Activation: running.Activation, Now: req.Now.Add(2 * time.Second),
	})
	if err != nil || failed.Execution.TerminalAt != nil || failed.Failure == nil || !failed.Failure.Retryable {
		t.Fatalf("failed payload = %#v, %v", failed, err)
	}
}

func TestReleaseInstallExecutionPayloadRejectsActivationRecordMismatch(t *testing.T) {
	req := releaseInstallExecutionRequest(time.Date(2026, 8, 5, 1, 2, 3, 0, time.UTC))
	created, err := PrepareReleaseInstallOperation(req)
	if err != nil {
		t.Fatal(err)
	}
	running, err := ApplyReleaseInstallOperationUpdate(created, UpdateReleaseInstallOperationRequest{
		ExecutionID: created.Execution.ID, ExpectedCursor: created.Execution.Cursor, Status: execution.StatusRunning,
		Phase: "enable", Progress: ReleaseInstallProgress{Kind: ReleaseInstallProgressIndeterminate}, Attempt: 1,
		MutationOutcome: mutation.OutcomeCommitted, Activation: created.Activation, Now: req.Now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	record := PluginRecord{PluginInstanceID: req.PluginInstanceID, EnableState: EnableDisabled}
	_, err = ApplyReleaseInstallOperationUpdate(running, UpdateReleaseInstallOperationRequest{
		ExecutionID: running.Execution.ID, ExpectedCursor: running.Execution.Cursor, Status: execution.StatusCompleted,
		Phase: "complete", Progress: ReleaseInstallProgress{Kind: ReleaseInstallProgressItems, Completed: 1, Total: 1}, Attempt: 1,
		MutationOutcome: mutation.OutcomeCommitted, PluginRecord: &record,
		Activation: ReleaseInstallActivation{Status: ReleaseInstallActivationEnabled}, Now: req.Now.Add(2 * time.Second),
	})
	if !errors.Is(err, ErrInvalidReleaseInstallOperation) {
		t.Fatalf("ApplyReleaseInstallOperationUpdate() error = %v, want %v", err, ErrInvalidReleaseInstallOperation)
	}
}

func TestReleaseInstallExecutionPayloadRejectsNonContractDigestShapes(t *testing.T) {
	now := time.Date(2026, 8, 5, 1, 2, 3, 0, time.UTC)
	prefixedMetadata := releaseInstallExecutionRequest(now)
	prefixedMetadata.Release.ReleaseMetadataSHA256 = "sha256:" + prefixedMetadata.Release.ReleaseMetadataSHA256
	if _, err := PrepareReleaseInstallOperation(prefixedMetadata); !errors.Is(err, ErrInvalidReleaseInstallOperation) {
		t.Fatalf("prefixed release metadata digest error = %v", err)
	}

	unprefixedPackage := releaseInstallExecutionRequest(now)
	unprefixedPackage.Release.PackageSHA256 = strings.TrimPrefix(unprefixedPackage.Release.PackageSHA256, "sha256:")
	if _, err := PrepareReleaseInstallOperation(unprefixedPackage); !errors.Is(err, ErrInvalidReleaseInstallOperation) {
		t.Fatalf("unprefixed package digest error = %v", err)
	}
}

func TestReleaseInstallExecutionPayloadAcceptsPublisherReleaseRefDigestShapes(t *testing.T) {
	reference := releasepublisher.PluginReleaseRefV1{
		SourceID: "official", Channel: "stable", ReleaseMetadataRef: "containers-4.1.0",
		ReleaseMetadataSHA256: strings.Repeat("a", 64), PublisherID: "floegence", PluginID: "com.floegence.containers", Version: "4.1.0",
		ExpectedHashes: releasepublisher.PackageHashSetV1{
			PackageSHA256: "sha256:" + strings.Repeat("b", 64), ManifestSHA256: "sha256:" + strings.Repeat("c", 64), EntriesSHA256: "sha256:" + strings.Repeat("d", 64),
		},
	}
	req := StartReleaseInstallOperationRequest{
		RequestID: "request_install_containers", ExecutionID: "operation_install_containers", PluginInstanceID: "plugini_containers",
		Release: ReleaseInstallIdentity{
			SourceID: reference.SourceID, Channel: reference.Channel, ReleaseMetadataRef: reference.ReleaseMetadataRef,
			ReleaseMetadataSHA256: reference.ReleaseMetadataSHA256, PublisherID: reference.PublisherID,
			PluginID: reference.PluginID, Version: reference.Version,
			PackageSHA256: reference.ExpectedHashes.PackageSHA256, ManifestSHA256: reference.ExpectedHashes.ManifestSHA256, EntriesSHA256: reference.ExpectedHashes.EntriesSHA256,
		},
		Activation: ReleaseInstallActivationRequest{Mode: ReleaseInstallActivationAutomatic},
		Now:        time.Date(2026, 8, 5, 1, 2, 3, 0, time.UTC),
	}
	if _, err := PrepareReleaseInstallOperation(req); err != nil {
		t.Fatalf("publisher release ref payload error = %v", err)
	}
}

func releaseInstallExecutionRequest(now time.Time) StartReleaseInstallOperationRequest {
	return StartReleaseInstallOperationRequest{
		RequestID: "request_install_example", ExecutionID: "operation_install_example", PluginInstanceID: "plugini_example",
		Release: ReleaseInstallIdentity{
			SourceID: "official", Channel: "stable", ReleaseMetadataRef: "example-1.2.3",
			ReleaseMetadataSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			PublisherID:           "example", PluginID: "com.example.plugin", Version: "1.2.3",
			PackageSHA256:  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			ManifestSHA256: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			EntriesSHA256:  "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		},
		Activation: ReleaseInstallActivationRequest{Mode: ReleaseInstallActivationAutomatic},
		Now:        now,
	}
}
