package controlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/execution"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/security"
)

func TestInstallPermissionMigrationPreservesReleasedState(t *testing.T) {
	for version := 1; version <= 7; version++ {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			db, path := pluginDataHistoricalDatabase(t, min(version, 4))
			ctx := context.Background()
			if version >= 5 {
				if err := migrateBackgroundIntervals(ctx, db); err != nil {
					t.Fatal(err)
				}
			}
			if version >= 6 {
				if err := migrateInspectedInstalls(ctx, db); err != nil {
					t.Fatal(err)
				}
			}
			if version >= 7 {
				if err := migrateOpenDistribution(ctx, db); err != nil {
					t.Fatal(err)
				}
			}
			db.Close()
			for range 2 {
				s, err := Open(ctx, Config{Path: path})
				if err != nil {
					t.Fatal(err)
				}
				var value string
				if err := s.db.QueryRow("SELECT value_json FROM control_metadata WHERE key='upgrade-preserved'").Scan(&value); err != nil || value != "original" {
					t.Fatal("released state lost", err)
				}
				s.Close()
			}
		})
	}
}

type failInstallPermissionMigration struct{ *sql.Tx }

func (q failInstallPermissionMigration) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if query == "UPDATE control_schema SET version=8 WHERE id=1 AND version=7" {
		return nil, errors.New("injected write failure")
	}
	return q.Tx.ExecContext(ctx, query, args...)
}

func TestInstallPermissionMigrationRollbackAndFutureState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sqlite")
	s, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE control_schema SET version=7"); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateInstallPermissions(context.Background(), failInstallPermissionMigration{tx}); err == nil {
		t.Fatal("write failure ignored")
	}
	tx.Rollback()
	var version int
	if err := s.db.QueryRow("SELECT version FROM control_schema").Scan(&version); err != nil || version != 7 {
		t.Fatal("partial migration", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := migrateInstallPermissions(ctx, s.db); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", err)
	}
	if _, err := s.db.Exec("UPDATE control_schema SET version=999"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	before, _ := os.ReadFile(path)
	if reopened, err := Open(context.Background(), Config{Path: path}); err == nil {
		reopened.Close()
		t.Fatal("future schema accepted")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("future schema changed")
	}
}

func TestInstallPermissionChoiceSurvivesRestartAndBindsRepeat(t *testing.T) {
	ctx := pluginDataCatalogContext("env", "user")
	path := filepath.Join(t.TempDir(), "control.sqlite")
	s, err := Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	owner := ExecutionOwner{OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel"}
	op := InspectedInstall{RequestID: "approved", InspectionID: "inspection", PluginID: "example.plugin", Version: "1.0.0", PackageSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Execution: execution.Execution{PluginInstanceID: "instance", Kind: execution.KindOperation}, ApprovedPermissions: []string{"documents.read"}}
	if _, _, err = s.Executions().StartInspectedInstall(ctx, owner, op); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.Executions().GetInspectedInstall(ctx, owner, op.RequestID)
	if err != nil || len(got.ApprovedPermissions) != 1 || got.ApprovedPermissions[0] != "documents.read" {
		t.Fatal("choice lost", got, err)
	}
	op.ApprovedPermissions = nil
	if _, _, err = s.Executions().StartInspectedInstall(ctx, owner, op); !errors.Is(err, ErrStateConflict) {
		t.Fatal("changed consent replaced request", err)
	}
}

func TestInstallPermissionsShareThePackageCommitPoint(t *testing.T) {
	for _, operation := range []string{"install", "update", "data_upgrade"} {
		for _, fail := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/failure=%v", operation, fail), func(t *testing.T) {
				ctx := pluginDataCatalogContext("env", "user")
				s := openPluginDataCatalogStore(t)
				defer s.Close()
				record, binding, shape := freshPluginDataCatalogInstall(t, "env", "instance")
				now := time.Now().UTC()
				grant, err := permissions.NewGrant(permissions.GrantRequest{PluginInstanceID: "instance", PermissionID: "documents.read", GrantedBy: "user", Now: now})
				if err != nil {
					t.Fatal(err)
				}
				var current registry.PluginRecord
				if operation != "install" {
					current, err = s.InstallCommit(ctx, record, nil, binding, shape, now)
					if err != nil {
						t.Fatal(err)
					}
				}
				if fail {
					if _, err := s.db.Exec(`CREATE TRIGGER reject_install_permission BEFORE INSERT ON permission_grants BEGIN SELECT RAISE(ABORT,'injected grant failure'); END`); err != nil {
						t.Fatal(err)
					}
				}
				if operation == "install" {
					_, err = s.InstallCommit(ctx, record, nil, binding, shape, now, grant)
				} else {
					next := pluginDataUpgradeRecord(t, current, "2.0.0")
					next.PackageSourceProvenance = current.PackageSourceProvenance
					next.PackageSourceProvenance.PackageSHA256 = next.PackageHash
					next.ExecutionApproval = current.ExecutionApproval
					next.ExecutionApproval.Status = registry.ExecutionApprovalUserApproved
					next.ExecutionApproval.PackageSHA256 = next.PackageHash
					if operation == "update" {
						_, err = s.Registry().UpdateExternalPackage(ctx, "env", registry.InstallExternalPackageRequest{Intent: registry.ExternalPackageUpdate, Record: next, ExpectedManagementRevision: current.ManagementRevision, Now: now}, grant)
					} else {
						active := binding
						active.GenerationID = "next-generation"
						active.Revision++
						_, err = s.CommitPluginDataUpgrade(ctx, current, next, binding, active, now, true, grant)
					}
				}
				if (err != nil) != fail {
					t.Fatal("unexpected transaction result", err)
				}
				var grants int
				if err := s.db.QueryRow("SELECT count(*) FROM permission_grants").Scan(&grants); err != nil {
					t.Fatal(err)
				}
				if fail && grants != 0 || !fail && grants != 1 {
					t.Fatal("partial grants", grants)
				}
				got, readErr := s.Registry().GetPlugin(ctx, "env", "instance")
				if fail {
					if operation == "install" && !errors.Is(readErr, registry.ErrNotFound) {
						t.Fatal("partial install", got, readErr)
					}
					if operation != "install" && (readErr != nil || got.ActiveFingerprint != current.ActiveFingerprint) {
						t.Fatal("partial update", got, readErr)
					}
				}
			})
		}
	}
}

func TestExternalUpdatesPreserveGrantsRevocationsAndPolicy(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(fmt.Sprint(upgrade), func(t *testing.T) {
			ctx := pluginDataCatalogContext("env", "user")
			s := openPluginDataCatalogStore(t)
			defer s.Close()
			current := putPluginDataCatalogRecord(t, s, ctx, "instance")
			snapshot, err := s.Registry().GetAuthorization(ctx, "env", "instance")
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"documents.read", "documents.write"} {
				snapshot, err = registry.PrepareGrantPermission(snapshot, permissions.GrantRequest{PluginInstanceID: "instance", PermissionID: id, GrantedBy: "user"}, registry.AuthorizationRevisionsFromRecord(snapshot.Plugin))
				if err != nil {
					t.Fatal(err)
				}
			}
			snapshot, err = registry.PrepareRevokePermission(snapshot, permissions.RevokeRequest{PluginInstanceID: "instance", PermissionID: "documents.write"}, registry.AuthorizationRevisionsFromRecord(snapshot.Plugin))
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err = registry.PrepareSecurityPolicy(snapshot, security.PutPolicyRequest{PluginInstanceID: "instance", DeniedMethods: []string{"danger.run"}}, registry.AuthorizationRevisionsFromRecord(snapshot.Plugin))
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Registry().ReplaceAuthorizationSnapshot(ctx, snapshot, registry.AuthorizationRevisionsFromRecord(current)); err != nil {
				t.Fatal(err)
			}
			current = snapshot.Plugin
			next := pluginDataUpgradeRecord(t, current, "2.0.0")
			next.PackageSourceProvenance = current.PackageSourceProvenance
			next.PackageSourceProvenance.PackageSHA256 = next.PackageHash
			next.ExecutionApproval = current.ExecutionApproval
			next.ExecutionApproval.Status = registry.ExecutionApprovalUserApproved
			next.ExecutionApproval.PackageSHA256 = next.PackageHash
			if upgrade {
				previous, _, err := s.GetBinding(ctx, "instance")
				if err != nil {
					t.Fatal(err)
				}
				active := previous
				active.GenerationID = "next"
				active.Revision++
				_, err = s.CommitPluginDataUpgrade(ctx, current, next, previous, active, time.Now(), true)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				_, err = s.Registry().UpdateExternalPackage(ctx, "env", registry.InstallExternalPackageRequest{Intent: registry.ExternalPackageUpdate, Record: next, ExpectedManagementRevision: current.ManagementRevision})
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := s.Registry().GetAuthorization(ctx, "env", "instance")
			if err != nil || len(got.Grants) != 2 || !permissions.Active(got.Grants[0], time.Now()) || permissions.Active(got.Grants[1], time.Now()) || got.Policy == nil || len(got.Policy.DeniedMethods) != 1 || got.Policy.DeniedMethods[0] != "danger.run" {
				t.Fatal("update changed user authorization", got, err)
			}
		})
	}
}
